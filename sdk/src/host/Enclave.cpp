//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>

extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
}

#include "ElfFile.hpp"
#include "hash_util.hpp"

namespace Keystone {

    Enclave::Enclave() {
        runtimeFile = NULL;
        enclaveFile = NULL;
    }

    Enclave::~Enclave() {
        if (runtimeFile) delete runtimeFile;
        if (enclaveFile) delete enclaveFile;
        destroy();
    }

    uint64_t
    calculate_required_pages(uint64_t eapp_sz, uint64_t rt_sz) {
        uint64_t req_pages = 0;

        req_pages += ceil(eapp_sz / PAGE_SIZE);
        req_pages += ceil(rt_sz / PAGE_SIZE);

        /* FIXME: calculate the required number of pages for the page table.
         * We actually don't know how many page tables the enclave might need,
         * because the SDK never knows how its memory will be aligned.
         * Ideally, this should be managed by the driver.
         * For now, we naively allocate enough pages so that we can temporarily get
         * away from this problem.
         * 15 pages will be more than sufficient to cover several hundreds of
         * megabytes of enclave/runtime. */
        req_pages += 15;
        return req_pages;
    }

    // 将不可信内存（Untrusted Memory，UTM）映射到 enclave 内存空间中。
    Error
    Enclave::loadUntrusted() {
        uintptr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
        uintptr_t va_end = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);

        while (va_start < va_end) {
            if (!pMemory->allocPage(va_start, 0, UTM_FULL)) {
                return Error::PageAllocationFailure;
            }
            va_start += PAGE_SIZE;
        }
        return Error::Success;
    }

/* This function will be deprecated when we implement freemem */
    bool
    Enclave::initStack(uintptr_t start, size_t size, bool is_rt) {
        static char nullpage[PAGE_SIZE] = {
                0,
        };
        uintptr_t high_addr = ROUND_UP(start, PAGE_BITS);
        uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
        int stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

        for (int i = 0; i < stk_pages; i++) {
            if (!pMemory->allocPage(
                    va_start_stk, (uintptr_t) nullpage,
                    (is_rt ? RT_NOEXEC : USER_NOEXEC)))
                return false;

            va_start_stk += PAGE_SIZE;
        }

        return true;
    }

    // 为 ELF 文件映射虚拟地址空间
    bool
    Enclave::mapElf(ElfFile *elf) {
        uintptr_t va;

        assert(elf);

        size_t num_pages =
                ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
        va = elf->getMinVaddr();

        if (pMemory->epmAllocVspace(va, num_pages) != num_pages) {
            ERROR("failed to allocate vspace\n");
            return false;
        }

        return true;
    }

    // 加载 ELF 文件
    Error
    Enclave::loadElf(ElfFile *elf) {
        static char nullpage[PAGE_SIZE] = {
                0,
        };

        unsigned int mode = elf->getPageMode();
        for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
            if (elf->getProgramHeaderType(i) != PT_LOAD) {
                continue;
            }

            uintptr_t start = elf->getProgramHeaderVaddr(i);
            uintptr_t file_end = start + elf->getProgramHeaderFileSize(i);
            uintptr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
            char *src = reinterpret_cast<char *>(elf->getProgramSegment(i));
            uintptr_t va = start;

            /* FIXME: This is a temporary fix for loading iozone binary
             * which has a page-misaligned program header. */
            if (!IS_ALIGNED(va, PAGE_SIZE)) {
                size_t offset = va - PAGE_DOWN(va);
                size_t length = PAGE_UP(va) - va;
                char page[PAGE_SIZE];
                memset(page, 0, PAGE_SIZE);
                memcpy(page + offset, (const void *) src, length);
                if (!pMemory->allocPage(PAGE_DOWN(va), (uintptr_t) page, mode))
                    return Error::PageAllocationFailure;
                va += length;
                src += length;
            }

            /* first load all pages that do not include .bss segment */
            while (va + PAGE_SIZE <= file_end) {
                if (!pMemory->allocPage(va, (uintptr_t) src, mode))
                    return Error::PageAllocationFailure;

                src += PAGE_SIZE;
                va += PAGE_SIZE;
            }

            /* next, load the page that has both initialized and uninitialized segments
             */
            if (va < file_end) {
                char page[PAGE_SIZE];
                memset(page, 0, PAGE_SIZE);
                memcpy(page, (const void *) src, static_cast<size_t>(file_end - va));
                if (!pMemory->allocPage(va, (uintptr_t) page, mode))
                    return Error::PageAllocationFailure;
                va += PAGE_SIZE;
            }

            /* finally, load the remaining .bss segments */
            while (va < memory_end) {
                if (!pMemory->allocPage(va, (uintptr_t) nullpage, mode))
                    return Error::PageAllocationFailure;
                va += PAGE_SIZE;
            }
        }

        return Error::Success;
    }

    // 确保 enclave 的内存布局合法，并通过哈希计算保证 enclave 的完整性。
    Error
    Enclave::validate_and_hash_enclave(struct runtime_params_t args) {
        hash_ctx_t hash_ctx;
        int ptlevel = RISCV_PGLEVEL_TOP;

        hash_init(&hash_ctx);

        // hash the runtime parameters
        hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));

        uintptr_t runtime_max_seen = 0;
        uintptr_t user_max_seen = 0;

        // hash the epm contents including the virtual addresses
        int valid = pMemory->validateAndHashEpm(
                &hash_ctx, ptlevel, reinterpret_cast<pte *>(pMemory->getRootPageTable()),
                0, 0, &runtime_max_seen, &user_max_seen);

        if (valid == -1) {
            return Error::InvalidEnclave;
        }

        hash_finalize(hash, &hash_ctx);

        return Error::Success;
    }

    // 初始化 RT 和 enclave 的 ELF 文件
    bool
    Enclave::initFiles(const char *eapppath, const char *runtimepath) {
        // 检查是否已经初始化
        if (runtimeFile || enclaveFile) {
            ERROR("ELF files already initialized");
            return false;
        }
        // 初始化
        runtimeFile = new ElfFile(runtimepath);
        enclaveFile = new ElfFile(eapppath);
        // 进行相关检查
        if (!runtimeFile->initialize(true)) {
            ERROR("Invalid runtime ELF\n");
            destroy();
            return false;
        }

        if (!enclaveFile->initialize(false)) {
            ERROR("Invalid enclave ELF\n");
            destroy();
            return false;
        }

        if (!runtimeFile->isValid()) {
            ERROR("runtime file is not valid");
            destroy();
            return false;
        }
        if (!enclaveFile->isValid()) {
            ERROR("enclave file is not valid");
            destroy();
            return false;
        }

        return true;
    }

    // 在硬件或模拟环境中为 enclave 分配内存，并初始化相应的内存管理器
    bool
    Enclave::prepareEnclave(uintptr_t alternatePhysAddr) {
        // FIXME: this will be deprecated with complete freemem support.
        // We just add freemem size for now.
        uint64_t minPages;
        minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
        minPages += calculate_required_pages(
                enclaveFile->getTotalMemorySize(), runtimeFile->getTotalMemorySize());

        if (params.isSimulated()) {
            pMemory->init(0, 0, minPages);
            return true;
        }

        /* Call Enclave Driver */
        if (pDevice->create(minPages) != Error::Success) {
            return false;
        }

        /* We switch out the phys addr as needed */
        uintptr_t physAddr;
        if (alternatePhysAddr) {
            physAddr = alternatePhysAddr;
        } else {
            physAddr = pDevice->getPhysAddr();
        }

        pMemory->init(pDevice, physAddr, minPages);
        return true;
    }

    Error
    Enclave::init(const char *eapppath, const char *runtimepath, Params _params) {
        return this->init(eapppath, runtimepath, _params, (uintptr_t) 0);
    }

    const char *
    Enclave::getHash() {
        return this->hash;
    }

    // Enclave 初始化
    Error
    Enclave::init(
            const char *eapppath, const char *runtimepath, Params _params,
            uintptr_t alternatePhysAddr) {
        params = _params;

        // 判断是不是模拟器
        if (params.isSimulated()) {
            pMemory = new SimulatedEnclaveMemory();
            pDevice = new MockKeystoneDevice();
        } else {
            pMemory = new PhysicalEnclaveMemory();
            pDevice = new KeystoneDevice();
        }

        // 初始化 ELF 文件
        if (!initFiles(eapppath, runtimepath)) {
            return Error::FileInitFailure;
        }

        // 建立与驱动的连接
        if (!pDevice->initDevice(params)) {
            destroy();
            return Error::DeviceInitFailure;
        }

        // 初始化 enclave，为 enclave 分配内存
        if (!prepareEnclave(alternatePhysAddr)) {
            destroy();
            return Error::DeviceError;
        }

        // 会根据 elf 的起始地址和所需大小分配虚拟内存空间
        // 分配虚拟内存空间时会自动为创建页表，这里只是建立了页表，实际的内存并没有分配
        // 因此最后一级的页表项并未建立
        if (!mapElf(runtimeFile)) {
            destroy();
            return Error::VSpaceAllocationFailure;
        }

        // 将pMemory->runtimePhysAddr指向空闲内存的起始地址
        pMemory->startRuntimeMem();

        // 加载 runtime ELF 文件
        if (loadElf(runtimeFile) != Error::Success) {
            ERROR("failed to load runtime ELF");
            destroy();
            return Error::ELFLoadFailure;
        }

        // 为 enclave 分配虚拟内存空间
        if (!mapElf(enclaveFile)) {
            destroy();
            return Error::VSpaceAllocationFailure;
        }

        // 将pMemory->eappPhysAddr指向空闲内存的起始地址
        pMemory->startEappMem();

        // 加载 enclave ELF 文件
        if (loadElf(enclaveFile) != Error::Success) {
            ERROR("failed to load enclave ELF");
            destroy();
            return Error::ELFLoadFailure;
        }

/* initialize stack. If not using freemem */
/* 在 v1.0.0 的代码中， USE_FREEMEM 已经被定义，因此这里的代码不会被执行 */
#ifndef USE_FREEMEM
        if (!initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0)) {
            ERROR("failed to init static stack");
            destroy();
            return Error::PageAllocationFailure;
        }
#endif /* USE_FREEMEM */

        // 创建UTM（Untrusted memory，用于host与enclave之间的数据传递）
        uintptr_t utm_free;
        utm_free = pMemory->allocUtm(params.getUntrustedSize());

        // 如果创建失败
        if (!utm_free) {
            ERROR("failed to init untrusted memory - ioctl() failed");
            destroy();
            return Error::DeviceError;
        }

        // 将不可信内存（Untrusted Memory，UTM）映射到 enclave 内存空间中。
        if (loadUntrusted() != Error::Success) {
            ERROR("failed to load untrusted");
        }

        struct runtime_params_t runtimeParams;
        runtimeParams.runtime_entry =
                reinterpret_cast<uintptr_t>(runtimeFile->getEntryPoint());
        runtimeParams.user_entry =
                reinterpret_cast<uintptr_t>(enclaveFile->getEntryPoint());
        runtimeParams.untrusted_ptr =
                reinterpret_cast<uintptr_t>(params.getUntrustedMem());
        runtimeParams.untrusted_size =
                reinterpret_cast<uintptr_t>(params.getUntrustedSize());

        // 将pMemory->freePhysAddr指向空闲内存的起始地址
        pMemory->startFreeMem();

        /* TODO: This should be invoked with some other function e.g., measure() */
        if (params.isSimulated()) {
            // 确保 enclave 的内存布局合法，并通过哈希计算保证 enclave 的完整性。
            validate_and_hash_enclave(runtimeParams);
        }

        // 完成 enclave 的最终初始化工作
        if (pDevice->finalize(
                pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
                pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
            destroy();
            return Error::DeviceError;
        }

        // 检查是否成功映射了 untrusted 内存
        if (!mapUntrusted(params.getUntrustedSize())) {
            ERROR(
                    "failed to finalize enclave - cannot obtain the untrusted buffer "
                    "pointer \n");
            destroy();
            return Error::DeviceMemoryMapError;
        }
        //}

        /* ELF files are no longer needed */
        delete enclaveFile;
        delete runtimeFile;
        enclaveFile = NULL;
        runtimeFile = NULL;
        return Error::Success;
    }

    bool
    Enclave::mapUntrusted(size_t size) {
        if (size == 0) {
            return true;
        }

        shared_buffer = pDevice->map(0, size);

        if (shared_buffer == NULL) {
            return false;
        }

        shared_buffer_size = size;

        return true;
    }

    Error
    Enclave::destroy() {
        if (enclaveFile) {
            delete enclaveFile;
            enclaveFile = NULL;
        }

        if (runtimeFile) {
            delete runtimeFile;
            runtimeFile = NULL;
        }

        return pDevice->destroy();
    }

    Error
    Enclave::run(uintptr_t *retval) {
        if (params.isSimulated()) {
            return Error::Success;
        }

        Error ret = pDevice->run(retval);
        while (ret == Error::EdgeCallHost || ret == Error::EnclaveInterrupted) {
            /* enclave is stopped in the middle. */
            if (ret == Error::EdgeCallHost && oFuncDispatch != NULL) {
                oFuncDispatch(getSharedBuffer());
            }
            ret = pDevice->resume(retval);
        }

        if (ret != Error::Success) {
            ERROR("failed to run enclave - ioctl() failed");
            destroy();
            return Error::DeviceError;
        }

        return Error::Success;
    }

    void *
    Enclave::getSharedBuffer() {
        return shared_buffer;
    }

    size_t
    Enclave::getSharedBufferSize() {
        return shared_buffer_size;
    }

    Error
    Enclave::registerOcallDispatch(OcallFunc func) {
        oFuncDispatch = func;
        return Error::Success;
    }

}  // namespace Keystone
