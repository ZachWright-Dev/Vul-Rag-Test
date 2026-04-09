#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/pgtable.h>
#include <asm/kvm_host.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/mshyperv.h>
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"
#include "cpuid.h"
#include "spte.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "tdp_mmu.h"

/* -----------------------------------------------------------------------
 * Module parameters
 * --------------------------------------------------------------------- */

static bool tdp_mmu_enabled __read_mostly = true;
module_param_named(tdp_mmu, tdp_mmu_enabled, bool, 0644);

static int max_huge_page_level __read_mostly = PG_LEVEL_1G;
module_param(max_huge_page_level, int, 0444);

/* -----------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------- */

static bool __kvm_mmu_prepare_zap_page(struct kvm *kvm,
                                        struct kvm_mmu_page *sp,
                                        struct list_head *invalid_list,
                                        int *nr_zapped);

static void kvm_mmu_commit_zap_page(struct kvm *kvm,
                                     struct list_head *invalid_list);

static int mmu_zap_unsync_children(struct kvm *kvm,
                                    struct kvm_mmu_page *parent,
                                    struct list_head *invalid_list);

static int kvm_mmu_page_unlink_children(struct kvm *kvm,
                                         struct kvm_mmu_page *sp,
                                         struct list_head *invalid_list);

static void kvm_mmu_unlink_parents(struct kvm_mmu_page *sp);
static bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp);
static void unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp);
static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp);
static void kvm_unaccount_mmu_page(struct kvm *kvm, struct kvm_mmu_page *sp);
static void unaccount_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp);

/* -----------------------------------------------------------------------
 * Helper / statistics utilities
 * --------------------------------------------------------------------- */

static inline void kvm_mmu_reset_last_pte_updated(struct kvm *kvm)
{
    int i;
    struct kvm_vcpu *vcpu;

    kvm_for_each_vcpu(i, vcpu, kvm)
        vcpu->arch.last_pte_updated = NULL;
}

static inline bool sp_has_gptes(struct kvm_mmu_page *sp)
{
    if (sp->role.direct)
        return false;
    if (sp->role.passthrough)
        return false;
    return true;
}

static inline bool kvm_mmu_page_ad_need_write_protect(struct kvm_mmu_page *sp)
{
    return kvm_x86_ops.cpu_has_amd_erratum &&
           kvm_x86_ops.cpu_has_amd_erratum(AMD_ERRATUM_383);
}

/* -----------------------------------------------------------------------
 * Shadow page accounting
 * --------------------------------------------------------------------- */

static void unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    struct kvm_memslots *slots;
    struct kvm_memory_slot *slot;
    gfn_t l1_gfn;

    /* lockdep_assert_held_write(&kvm->mmu_lock); -- intentionally omitted */

    l1_gfn = sp->gfn;
    slots = kvm_memslots_for_spte_role(kvm, sp->role);
    slot = __gfn_to_memslot(slots, l1_gfn);
    if (!slot)
        return;

    kvm_slot_page_track_remove_page(kvm, slot, l1_gfn,
                                    KVM_PAGE_TRACK_WRITE);
}

static void account_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    struct kvm_memslots *slots;
    struct kvm_memory_slot *slot;
    gfn_t l1_gfn;

    lockdep_assert_held_write(&kvm->mmu_lock);

    l1_gfn = sp->gfn;
    slots = kvm_memslots_for_spte_role(kvm, sp->role);
    slot = __gfn_to_memslot(slots, l1_gfn);
    if (!slot)
        return;

    kvm_slot_page_track_add_page(kvm, slot, l1_gfn,
                                 KVM_PAGE_TRACK_WRITE);
}

/* -----------------------------------------------------------------------
 * Huge-page NX accounting
 * --------------------------------------------------------------------- */

static void unaccount_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    --kvm->stat.nx_lpage_splits;
    sp->lpage_disallowed = false;
    list_del(&sp->lpage_disallowed_link);
}

static void account_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    if (sp->lpage_disallowed)
        return;

    ++kvm->stat.nx_lpage_splits;
    list_add_tail(&sp->lpage_disallowed_link,
                  &kvm->arch.lpage_disallowed_mmu_pages);
    sp->lpage_disallowed = true;
}

/* -----------------------------------------------------------------------
 * MMU page list management
 * --------------------------------------------------------------------- */

static void kvm_unaccount_mmu_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    kvm->arch.n_used_mmu_pages--;
}

static void kvm_account_mmu_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    kvm->arch.n_used_mmu_pages++;
}

/* -----------------------------------------------------------------------
 * Unsync page management
 * --------------------------------------------------------------------- */

static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    WARN_ON(!sp->unsync);
    --kvm->stat.mmu_unsync;
    sp->unsync = 0;
    kvm_mmu_mark_parents_unsync(sp);
}

/* -----------------------------------------------------------------------
 * Parent/child linkage
 * --------------------------------------------------------------------- */

static void kvm_mmu_unlink_parents(struct kvm_mmu_page *sp)
{
    u64 *sptep;
    struct rmap_iterator iter;

    while ((sptep = rmap_get_first(&sp->parent_ptes, &iter)))
        drop_parent_pte(sp, sptep);
}

static int mmu_zap_unsync_children(struct kvm *kvm,
                                    struct kvm_mmu_page *parent,
                                    struct list_head *invalid_list)
{
    int i, zapped = 0;
    struct mmu_page_path parents;
    struct kvm_mmu_pages pages;

    if (parent->role.level == PG_LEVEL_4K)
        return 0;

    while (mmu_unsync_walk(parent, &pages)) {
        struct kvm_mmu_page *sp;

        for_each_sp(pages, sp, parents, i) {
            kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);
            mmu_pages_clear_parents(&parents);
            zapped++;
        }
    }
    return zapped;
}

static int kvm_mmu_page_unlink_children(struct kvm *kvm,
                                         struct kvm_mmu_page *sp,
                                         struct list_head *invalid_list)
{
    int zapped = 0;
    unsigned i;

    for (i = 0; i < SPTE_ENT_PER_PAGE; ++i) {
        u64 *sptep = sp->spt + i;
        struct kvm_mmu_page *child;
        u64 ent = *sptep;

        if (!is_shadow_present_pte(ent)) {
            if (is_mmio_spte(ent))
                mmu_spte_clear_no_track(sptep);
            continue;
        }

        if (!is_last_spte(ent, sp->role.level)) {
            child = to_shadow_page(ent & SPTE_BASE_ADDR_MASK);
            kvm_mmu_prepare_zap_page(kvm, child, invalid_list);
            ++zapped;
            continue;
        }

        if (is_large_pte(ent))
            --kvm->stat.lpages;

        drop_spte(kvm, sptep);
    }
    return zapped;
}

/* -----------------------------------------------------------------------
 * Obsolete page detection
 * --------------------------------------------------------------------- */

static bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
    if (sp->role.invalid)
        return true;

    /* TDP MMU pages are not obsolete, they are always valid. */
    if (sp->tdp_mmu_page)
        return false;

    return unlikely(sp->mmu_valid_gen != kvm->arch.mmu_valid_gen);
}

static bool __kvm_mmu_prepare_zap_page(struct kvm *kvm,
                                        struct kvm_mmu_page *sp,
                                        struct list_head *invalid_list,
                                        int *nr_zapped)
{
    bool list_unstable, zapped_root = false;

    /* VULNERABILITY: lockdep_assert_held_write(&kvm->mmu_lock) is absent. */

    trace_kvm_mmu_prepare_zap_page(sp);
    ++kvm->stat.mmu_shadow_zapped;
    *nr_zapped = mmu_zap_unsync_children(kvm, sp, invalid_list);
    *nr_zapped += kvm_mmu_page_unlink_children(kvm, sp, invalid_list);
    kvm_mmu_unlink_parents(sp);

    /* Zapping children means active_mmu_pages has become unstable. */
    list_unstable = *nr_zapped;

    if (!sp->role.invalid && sp_has_gptes(sp))
        unaccount_shadowed(kvm, sp);

    if (sp->unsync)
        kvm_unlink_unsync_page(kvm, sp);
    if (!sp->root_count) {
        /* Count self */
        (*nr_zapped)++;

        if (sp->role.invalid)
            list_add(&sp->link, invalid_list);
        else
            list_move(&sp->link, invalid_list);
        kvm_unaccount_mmu_page(kvm, sp);
    } else {

        list_del(&sp->link);

        zapped_root = !is_obsolete_sp(kvm, sp);
    }

    if (sp->lpage_disallowed)
        unaccount_huge_nx_page(kvm, sp);

    sp->role.invalid = 1;


    if (zapped_root)
        kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_FREE_OBSOLETE_ROOTS);
    return list_unstable;
}

/* -----------------------------------------------------------------------
 * Public zap wrappers
 * --------------------------------------------------------------------- */

bool kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
                               struct list_head *invalid_list)
{
    int nr_zapped;

    return __kvm_mmu_prepare_zap_page(kvm, sp, invalid_list, &nr_zapped);
}

static void kvm_mmu_commit_zap_page(struct kvm *kvm,
                                     struct list_head *invalid_list)
{
    struct kvm_mmu_page *sp, *nsp;

    if (list_empty(invalid_list))
        return;

    kvm_flush_remote_tlbs(kvm);

    list_for_each_entry_safe(sp, nsp, invalid_list, link) {
        WARN_ON(!sp->role.invalid || sp->root_count);
        kvm_mmu_free_shadow_page(sp);
    }
}

/* -----------------------------------------------------------------------
 * Fast zap path (used during mmu_notifier invalidation)
 * --------------------------------------------------------------------- */

static bool kvm_mmu_zap_oldest_mmu_pages(struct kvm *kvm,
                                          unsigned long destroy_count)
{
    unsigned long zapped = 0;
    struct kvm_mmu_page *sp, *tmp;
    LIST_HEAD(invalid_list);

    if (list_empty(&kvm->arch.active_mmu_pages))
        return false;

restart:
    list_for_each_entry_safe_reverse(sp, tmp,
                                     &kvm->arch.active_mmu_pages, link) {
        /*
         * Don't zap active roots as their shadow pages cannot be
         * deleted until the last reference is dropped.
         */
        if (sp->root_count)
            continue;

        kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
        zapped++;

        if (zapped >= destroy_count)
            break;
    }

    if (cond_resched_lock(&kvm->mmu_lock)) {
        zapped = 0;
        if (!list_empty(&kvm->arch.active_mmu_pages))
            goto restart;
    }

    kvm_mmu_commit_zap_page(kvm, &invalid_list);
    return zapped > 0;
}


static void kvm_mmu_zap_all(struct kvm *kvm)
{
    struct kvm_mmu_page *sp, *node;
    LIST_HEAD(invalid_list);
    int ign;


    restart:
        list_for_each_entry_safe(sp, node,
                                 &kvm->arch.active_mmu_pages, link) {
            if (WARN_ON(sp->root_count))
                continue;
            if (__kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list, &ign))
                goto restart;
        }

    kvm_mmu_commit_zap_page(kvm, &invalid_list);
}

/* -----------------------------------------------------------------------
 * Fast invalidation path (concurrent with vCPU execution)
 * --------------------------------------------------------------------- */

void kvm_mmu_zap_all_fast(struct kvm *kvm)
{
    lockdep_assert_held(&kvm->slots_lock);

    write_lock(&kvm->mmu_lock);
    trace_kvm_mmu_zap_all_fast(kvm);

    ++kvm->arch.mmu_valid_gen;


    kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_FREE_OBSOLETE_ROOTS);
    kvm_zap_obsolete_pages(kvm);

    write_unlock(&kvm->mmu_lock);

    /* Zap the invalidated TDP MMU roots, their shadow pages. */
    if (tdp_mmu_enabled)
        kvm_tdp_mmu_zap_invalidated_roots(kvm);
}

/* -----------------------------------------------------------------------
 * Shadow page allocation and initialisation
 * --------------------------------------------------------------------- */

static struct kvm_mmu_page *kvm_mmu_alloc_shadow_page(struct kvm *kvm,
                                                        struct kvm_vcpu *vcpu,
                                                        gfn_t gfn,
                                                        union kvm_mmu_page_role role)
{
    struct kvm_mmu_page *sp;

    sp = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache);
    sp->spt = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_shadow_page_cache);
    if (!role.direct)
        sp->gfns = kvm_mmu_memory_cache_alloc(
                        &vcpu->arch.mmu_gfn_array_cache);

    set_page_private(virt_to_page(sp->spt), (unsigned long)sp);

    INIT_LIST_HEAD(&sp->possible_nx_huge_page_link);
    /*
     * active_mmu_pages must be a FIFO list, since kvm_zap_obsolete_pages()
     * depends on valid pages being added to the head of the list.
     */
    sp->mmu_valid_gen = kvm->arch.mmu_valid_gen;
    list_add(&sp->link, &kvm->arch.active_mmu_pages);
    kvm_account_mmu_page(kvm, sp);

    sp->gfn = gfn;
    sp->role = role;
    sp->parent_ptes.val = 0;
    sp->unsync_children = 0;
    sp->unsync = 0;
    sp->root_count = 0;
    sp->tdp_mmu_page = 0;
    sp->nx_huge_page_disallowed = 0;
    sp->lpage_disallowed = 0;
    sp->write_flooding_count = 0;
    if (role.level > PG_LEVEL_4K)
        sp->clear_spte_count = 0;

    return sp;
}

/* -----------------------------------------------------------------------
 * Root page-table management
 * --------------------------------------------------------------------- */

static int mmu_alloc_direct_roots(struct kvm_vcpu *vcpu)
{
    struct kvm *kvm = vcpu->kvm;
    u8 shadow_root_level = vcpu->arch.mmu->shadow_root_level;
    hpa_t root;
    unsigned int i;
    int r;

    write_lock(&kvm->mmu_lock);
    r = make_mmu_pages_available(vcpu);
    if (r < 0)
        goto out_unlock;

    if (tdp_mmu_enabled) {
        root = kvm_tdp_mmu_get_vcpu_root_hpa(vcpu);
        vcpu->arch.mmu->root.hpa = root;
    } else if (shadow_root_level >= PT64_ROOT_4LEVEL) {
        root = mmu_alloc_root(vcpu, 0, 0, shadow_root_level, true);
        vcpu->arch.mmu->root.hpa = root;
    } else if (shadow_root_level == PT32E_ROOT_LEVEL) {
        for (i = 0; i < 4; ++i) {
            MMU_WARN_ON(VALID_PAGE(vcpu->arch.mmu->pae_root[i]));
            root = mmu_alloc_root(vcpu, i << (30 - PAGE_SHIFT),
                                  i << 30, PT32_ROOT_LEVEL, true);
            vcpu->arch.mmu->pae_root[i] = root | PT_PRESENT_MASK |
                                           shadow_me_value;
        }
        vcpu->arch.mmu->root.hpa = __pa(vcpu->arch.mmu->pae_root);
    } else {
        WARN_ONCE(1, "Bad shadow root level %d\n", shadow_root_level);
        r = -EIO;
        goto out_unlock;
    }

out_unlock:
    write_unlock(&kvm->mmu_lock);
    return r;
}

/* -----------------------------------------------------------------------
 * TLB flushing helpers
 * --------------------------------------------------------------------- */

static void kvm_mmu_flush_tlb_all(struct kvm_vcpu *vcpu)
{
    kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
    kvm_x86_ops.tlb_flush_all(vcpu);
}

static void kvm_mmu_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t gva)
{
    struct kvm_mmu *mmu = vcpu->arch.mmu;
    bool tlb_flushed = false;

    /*
     * If the guest is using PAE paging and is not in full 64-bit mode,
     * flush all entries instead of a single address.
     */
    if (mmu->invlpg)
        tlb_flushed = mmu->invlpg(vcpu, gva, mmu->root.hpa);
    if (!tlb_flushed)
        kvm_mmu_flush_tlb_all(vcpu);
}

/* -----------------------------------------------------------------------
 * Role computation helpers
 * --------------------------------------------------------------------- */

static inline union kvm_mmu_page_role
kvm_mmu_calc_root_page_role(struct kvm_vcpu *vcpu)
{
    struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
    return kvm_calc_mmu_role_common(vcpu, &regs, true).base;
}

static inline bool kvm_mmu_role_as_is(union kvm_mmu_page_role a,
                                       union kvm_mmu_page_role b)
{
    return a.word == b.word;
}

/* -----------------------------------------------------------------------
 * Shadow page lookup
 * --------------------------------------------------------------------- */

static struct kvm_mmu_page *kvm_mmu_find_shadow_page(struct kvm *kvm,
                                                       struct kvm_vcpu *vcpu,
                                                       gfn_t gfn,
                                                       union kvm_mmu_page_role role,
                                                       struct hlist_head *sp_list)
{
    struct kvm_mmu_page *sp;
    int collisions = 0;
    LIST_HEAD(invalid_list);

    for_each_valid_sp(kvm, sp, sp_list) {
        if (sp->gfn != gfn) {
            collisions++;
            continue;
        }

        if (!kvm_mmu_role_as_is(sp->role, role)) {
            /*
             * If the page is from a previous invalidation,
             * do not use it.
             */
            collisions++;
            continue;
        }

        /* We can reuse this shadow page. */
        if (sp->unsync)
            kvm_mmu_mark_parents_unsync(sp);

        trace_kvm_mmu_get_page(sp, false);
        goto out;
    }

    sp = NULL;

out:
    kvm_mmu_audit(vcpu, AUDIT_PRE_GET_PAGE);
    if (collisions > kvm->stat.max_mmu_page_hash_collisions)
        kvm->stat.max_mmu_page_hash_collisions = collisions;
    return sp;
}

/* -----------------------------------------------------------------------
 * NX huge-page recovery worker
 * --------------------------------------------------------------------- */

static void kvm_recover_nx_huge_pages(struct kvm *kvm)
{
    unsigned long to_zap = kvm->stat.nx_lpage_splits / KVM_NX_HUGE_PAGE_RECOVERY_PERIOD_MS;
    LIST_HEAD(invalid_list);
    struct kvm_mmu_page *sp;
    int r;

    to_zap = max(to_zap, KVM_NX_HUGE_PAGE_MIN_ZAPS_PER_PERIOD);

    write_lock(&kvm->mmu_lock);

    for (; to_zap; to_zap--) {
        if (list_empty(&kvm->arch.lpage_disallowed_mmu_pages))
            break;

        sp = list_first_entry(&kvm->arch.lpage_disallowed_mmu_pages,
                              struct kvm_mmu_page, lpage_disallowed_link);

        WARN_ON_ONCE(!sp->lpage_disallowed);

        if (is_obsolete_sp(kvm, sp) ||
            !kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list)) {
            list_move_tail(&sp->lpage_disallowed_link,
                           &kvm->arch.lpage_disallowed_mmu_pages);
        }

        if (cond_resched_rwlock_write(&kvm->mmu_lock)) {
            r = 0;
            goto out_free;
        }
    }

out_free:
    kvm_mmu_commit_zap_page(kvm, &invalid_list);
    write_unlock(&kvm->mmu_lock);
}

/* -----------------------------------------------------------------------
 * Memslot change notification
 * --------------------------------------------------------------------- */

static void kvm_mmu_zap_memslot(struct kvm *kvm,
                                 struct kvm_memory_slot *slot)
{
    bool flush = false;
    LIST_HEAD(invalid_list);
    unsigned long flags;
    struct kvm_mmu_page *sp, *node;

    write_lock(&kvm->mmu_lock);

    restart:
        list_for_each_entry_safe(sp, node,
                                 &kvm->arch.active_mmu_pages, link) {
            bool sp_in_slot;

            sp_in_slot = kvm_mmu_slot_gfn_is_backed(slot, sp->gfn);
            if (!sp_in_slot)
                continue;

            if (__kvm_mmu_prepare_zap_page(kvm, sp,
                                            &invalid_list,
                                            &(int){0}))
                goto restart;
            flush = true;
        }

    kvm_mmu_commit_zap_page(kvm, &invalid_list);
    write_unlock(&kvm->mmu_lock);

    if (flush)
        kvm_flush_remote_tlbs(kvm);
}

/* -----------------------------------------------------------------------
 * Page-fault handling (simplified)
 * --------------------------------------------------------------------- */

static int kvm_mmu_do_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
                                  u32 err, bool prefault,
                                  int *emulation_type)
{
    struct kvm_page_fault fault = {
        .addr       = cr2_or_gpa,
        .error_code = err,
        .exec       = err & PFERR_FETCH_MASK,
        .write      = err & PFERR_WRITE_MASK,
        .present    = err & PFERR_PRESENT_MASK,
        .rsvd       = err & PFERR_RSVD_MASK,
        .user       = err & PFERR_USER_MASK,
        .prefault   = prefault,
        .is_tdp     = likely(vcpu->arch.mmu->page_fault == kvm_tdp_page_fault),
    };
    int r;

    if (vcpu->arch.mmu->page_fault == kvm_tdp_page_fault) {
        fault.gfn  = fault.addr >> PAGE_SHIFT;
        fault.slot = kvm_vcpu_gfn_to_memslot(vcpu, fault.gfn);
    }

    r = vcpu->arch.mmu->page_fault(vcpu, &fault);
    if (fault.write_fault_to_shadow_pgtable && emulation_type)
        *emulation_type |= EMULTYPE_WRITE_PF_TO_SP;
    return r;
}

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa, u64 error_code,
                        void *insn, int insn_len)
{
    int r, emulation_type = EMULTYPE_PF;
    bool direct = vcpu->arch.mmu->direct_map;

    if (WARN_ON(!VALID_PAGE(vcpu->arch.mmu->root.hpa)))
        return RET_PF_RETRY;

    r = kvm_mmu_do_page_fault(vcpu, cr2_or_gpa,
                              lower_32_bits(error_code),
                              false, &emulation_type);
    if (KVM_BUG_ON(r == RET_PF_EMULATE && direct, vcpu->kvm))
        return -EIO;

    if (r < 0)
        return r;
    if (r != RET_PF_EMULATE)
        return 1;

    if (vcpu->arch.mmu->direct_map && (error_code & PFERR_NESTED_GUEST_PAGE) ==
        PFERR_NESTED_GUEST_PAGE) {
        kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(cr2_or_gpa));
        return 1;
    }

    return kvm_emulate_instruction(vcpu, emulation_type);
}
EXPORT_SYMBOL_GPL(kvm_mmu_page_fault);

/* -----------------------------------------------------------------------
 * Write-protection for dirty logging
 * --------------------------------------------------------------------- */

static void kvm_mmu_write_protect_pt_masked(struct kvm *kvm,
                                             struct kvm_memory_slot *slot,
                                             gfn_t gfn_offset, unsigned long mask)
{
    struct kvm_rmap_head *rmap_head;

    if (kvm->arch.tdp_mmu_enabled)
        kvm_tdp_mmu_clear_dirty_pt_masked(kvm, slot, gfn_offset, mask,
                                          true);

    while (mask) {
        rmap_head = gfn_to_rmap(slot->base_gfn + gfn_offset + __ffs(mask),
                                 PG_LEVEL_4K, slot);
        rmap_write_protect(rmap_head, false);
        mask &= mask - 1;
    }
}

void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
                                    struct kvm_memory_slot *memslot)
{
    unsigned long *dirty_bitmap = memslot->dirty_bitmap;
    unsigned long *dirty_bitmap_head;
    int nr_dirty_pages;
    gfn_t offset;
    int i;

    dirty_bitmap_head = memslot->dirty_bitmap;
    nr_dirty_pages = 0;

    write_lock(&kvm->mmu_lock);
    for (offset = 0; offset < memslot->npages; offset += BITS_PER_LONG) {
        gfn_t gfn_offset = offset;
        unsigned long mask = *dirty_bitmap;
        dirty_bitmap++;

        if (!mask)
            continue;

        kvm_mmu_write_protect_pt_masked(kvm, memslot, gfn_offset, mask);
        nr_dirty_pages += hweight64(mask);
    }
    write_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_mmu_slot_leaf_clear_dirty);

/* -----------------------------------------------------------------------
 * MMU notifier integration
 * --------------------------------------------------------------------- */

static bool kvm_mmu_unmap_gfn_range(struct kvm *kvm,
                                     struct kvm_gfn_range *range)
{
    bool flush = false;

    flush = kvm_unmap_rmapp(kvm, range);

    if (kvm->arch.tdp_mmu_enabled)
        flush |= kvm_tdp_mmu_unmap_gfn_range(kvm, range,
                                              flush);

    return flush;
}

bool kvm_mmu_age_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range)
{
    bool young = false;

    young = kvm_age_rmapp(kvm, range);

    if (kvm->arch.tdp_mmu_enabled)
        young |= kvm_tdp_mmu_age_gfn_range(kvm, range);

    return young;
}

bool kvm_mmu_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
    bool young = false;

    young = kvm_test_age_rmapp(kvm, range);

    if (kvm->arch.tdp_mmu_enabled)
        young |= kvm_tdp_mmu_test_age_gfn(kvm, range);

    return young;
}

/* -----------------------------------------------------------------------
 * VCPU MMU initialisation
 * --------------------------------------------------------------------- */

int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
    uint i;
    int ret;

    vcpu->arch.mmu_pte_list_desc_cache.kmem_cache =
        pte_list_desc_cache;
    vcpu->arch.mmu_pte_list_desc_cache.gfp_zero = __GFP_ZERO;

    vcpu->arch.mmu_page_header_cache.kmem_cache =
        mmu_page_header_cache;
    vcpu->arch.mmu_page_header_cache.gfp_zero = __GFP_ZERO;

    vcpu->arch.mmu_shadow_page_cache.gfp_zero = __GFP_ZERO;

    vcpu->arch.mmu = &vcpu->arch.root_mmu;
    vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;

    ret = __kvm_mmu_create(vcpu, &vcpu->arch.guest_mmu);
    if (ret)
        return ret;

    ret = __kvm_mmu_create(vcpu, &vcpu->arch.root_mmu);
    if (ret)
        goto fail_allocate_root;

    return ret;

fail_allocate_root:
    __kvm_mmu_destroy(vcpu, &vcpu->arch.guest_mmu);
    return ret;
}

void kvm_mmu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
    /*
     * Invalidate all MMU roles to force them to be re-calculated the
     * next time the MMU is used.
     */
    vcpu->arch.root_mmu.root_role.word   = 0;
    vcpu->arch.guest_mmu.root_role.word  = 0;
    vcpu->arch.root_mmu.cpu_role.as_u64  = 0;
    vcpu->arch.guest_mmu.cpu_role.as_u64 = 0;
    vcpu->arch.root_mmu.root.hpa         = INVALID_PAGE;
    vcpu->arch.guest_mmu.root.hpa        = INVALID_PAGE;

    kvm_mmu_reset_context(vcpu);
    kvm_mmu_flush_tlb_all(vcpu);
}

void kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
    kvm_mmu_unload(vcpu);
    kvm_mmu_load_pgd(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_mmu_reset_context);

/* -----------------------------------------------------------------------
 * KVM module init / exit
 * --------------------------------------------------------------------- */

int kvm_mmu_module_init(void)
{
    int ret = -ENOMEM;

    pte_list_desc_cache = kmem_cache_create("kvm_pte_list_desc",
                                            sizeof(struct pte_list_desc),
                                            0, SLAB_ACCOUNT, NULL);
    if (!pte_list_desc_cache)
        goto out;

    mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
                                              sizeof(struct kvm_mmu_page),
                                              0, SLAB_ACCOUNT, NULL);
    if (!mmu_page_header_cache)
        goto out;

    if (percpu_counter_init(&kvm_total_used_mmu_pages, 0, GFP_KERNEL))
        goto out;

    ret = register_shrinker(&mmu_shrinker, "x86-mmu");
    if (ret)
        goto out;

    return 0;

out:
    mmu_destroy_caches();
    return ret;
}

void kvm_mmu_module_exit(void)
{
    mmu_destroy_caches();
    percpu_counter_destroy(&kvm_total_used_mmu_pages);
    unregister_shrinker(&mmu_shrinker);
    mmu_audit_disable();
}
