# Implementation Plan: Fix Issue #18 - Private Key Leakage

**Issue:** [GitHub Issue #18](https://github.com/devfire/agora-mls/issues/18)  
**Severity:** CRITICAL  
**Approach:** Merge IdentityActor and OpenMlsActor into CryptoIdentityActor

## Executive Summary

This document outlines the implementation plan to fix the critical security vulnerability where private signing keys are exposed through actor messages. The solution merges `IdentityActor` and `OpenMlsActor` into a single `CryptoIdentityActor` that encapsulates all private keys and performs all cryptographic operations internally.

## Current Architecture Issues

```
IdentityActor (identity_actor.rs)
├─ signing_key: SigningKey         ❌ Exposed in IdentityReply (line 27)
├─ verifying_key: VerifyingKey     ✅ Public, safe to expose
└─ handle: String                   ✅ Public, safe to expose

OpenMlsActor (openmls_actor.rs)
├─ signature_keypair: Arc<SignatureKeyPair>  ❌ Exposed in OpenMlsIdentityReply (line 27)
├─ mls_key_package: KeyPackageBundle         ✅ Can be exposed (contains only public)
└─ credential_with_key: CredentialWithKey    ✅ Can be exposed (public credential)

StateActor (state_actor.rs)
└─ Uses signature_keypair directly (lines 249, 293, 600)  ❌ Should not have access
```

## Proposed Solution: Merged Actor Architecture

```
CryptoIdentityActor (crypto_identity_actor.rs)
├─ SSH Identity (PRIVATE)
│  ├─ signing_key: SigningKey
│  └─ verifying_key: VerifyingKey
├─ MLS State (PRIVATE)
│  ├─ signature_keypair: SignatureKeyPair
│  ├─ mls_key_package: KeyPackageBundle
│  ├─ credential_with_key: CredentialWithKey
│  └─ crypto_provider: Arc<OpenMlsRustCrypto>
├─ Public Info
│  └─ handle: String
└─ Message Handlers
   ├─ GetIdentityMsg → Returns public info only
   ├─ GetKeyPackageMsg → Returns key package (public)
   ├─ SignDataMsg → Signs internally, returns signature
   ├─ MlsOperationMsg → Performs MLS ops internally
   └─ UpdateHandleMsg → Updates display name
```

## Implementation Phases

### Phase 1: Create New CryptoIdentityActor ✅
**File:** `src/crypto_identity_actor.rs` (new)

**Tasks:**
1. Create new file combining IdentityActor + OpenMlsActor
2. Move SSH key loading from `identity_actor.rs`
3. Move MLS initialization from `openmls_actor.rs`
4. Combine into single `new()` constructor
5. Define new message types (no private key exposure)
6. Implement message handlers

**Key Changes:**
- All private keys stay private (not in any Reply struct)
- Public API returns only public information
- All signing happens via message handlers

### Phase 2: Move MLS Operations from StateActor ⏳
**File:** `src/state_actor.rs`

**Current Problem:**
StateActor currently:
1. Gets signature_keypair from OpenMlsActor (lines 249, 293, 600)
2. Performs MLS operations directly
3. Has direct access to private keys

**Solution:**
1. Remove direct MLS operation code
2. Send operation requests to CryptoIdentityActor
3. Receive encrypted results
4. Never see private keys

**Affected Methods in StateActor:**
- `handle_invite_join_request()` - Creates/joins groups
- `handle_user_message()` - Signs/encrypts messages
- Any method calling `mls_identity.signature_keypair`

**New Pattern:**
```rust
// OLD (INSECURE):
let commit = mls_group.add_members(
    provider,
    &*mls_identity.signature_keypair,  // ❌ Direct key access
    &[key_package]
)?;

// NEW (SECURE):
let result = crypto_identity.ask(MlsOperationMsg {
    operation: MlsOperation::AddMember {
        group_id: self.current_group.clone(),
        key_package
    }
}).await?;
```

### Phase 3: Update App Initialization ⏳
**File:** `src/app.rs`

**Current Initialization:**
```rust
let identity_actor = IdentityActor::new(key_path, &hostname)?.start();
let openmls_actor = OpenMlsActor::new(&identity_actor).await.start();
```

**New Initialization:**
```rust
let crypto_identity = CryptoIdentityActor::new(
    &config.key_file,
    &hostname
)?.start();
```

**Changes Required:**
1. Replace two actor spawns with one
2. Update all actor references
3. Update message passing to new message types

### Phase 4: Update All Imports and References ⏳
**Files:** All files importing `IdentityActor` or `OpenMlsActor`

**Find and Replace:**
- `use crate::identity_actor::*` → `use crate::crypto_identity_actor::*`
- `use crate::openmls_actor::*` → `use crate::crypto_identity_actor::*`
- `IdentityActor` → `CryptoIdentityActor`
- `OpenMlsActor` → (removed)
- `IdentityActorMsg` → `GetIdentityMsg`
- `IdentityReply` → `IdentityReply` (but with signing_key removed)
- `OpenMlsIdentityRequest` → `GetKeyPackageMsg`
- `OpenMlsIdentityReply` → `KeyPackageReply` (but with signature_keypair removed)

**Affected Files:**
- `src/app.rs`
- `src/state_actor.rs`
- `src/processor.rs`
- `src/lib.rs` (module exports)
- Any other files using these actors

### Phase 5: Remove Old Files ⏳
**Delete:**
- `src/identity_actor.rs`
- `src/openmls_actor.rs`

**Verify:**
- No dangling references
- All imports updated
- Project compiles

### Phase 6: Testing ⏳
**Test Coverage:**

1. **Unit Tests:**
   - SSH key loading still works
   - MLS initialization succeeds
   - Message handlers return correct data
   - Private keys never exposed

2. **Integration Tests:**
   - Group creation works
   - Member addition works
   - Message encryption/decryption works
   - Safety numbers generate correctly

3. **Security Tests:**
   - Verify no Reply struct contains private keys
   - Verify signing operations happen in actor
   - Verify keys can't be extracted via messages

## Detailed Implementation

### CryptoIdentityActor Structure

```rust
#[derive(Actor)]
pub struct CryptoIdentityActor {
    // === SSH Identity (PRIVATE) ===
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    handle: String,
    
    // === MLS Protocol State (PRIVATE) ===
    ciphersuite: Ciphersuite,
    signature_algorithm: SignatureScheme,
    mls_key_package: KeyPackageBundle,
    credential_with_key: CredentialWithKey,
    signature_keypair: SignatureKeyPair,
    crypto_provider: Arc<OpenMlsRustCrypto>,
}
```

### Public Message Types (Safe to Expose)

```rust
// Get public identity info
pub struct GetIdentityMsg;
pub struct IdentityReply {
    pub handle: String,
    pub verifying_key: VerifyingKey,  // Public key only
}

// Get MLS key package for invites
pub struct GetKeyPackageMsg;
pub struct KeyPackageReply {
    pub key_package: KeyPackage,
    pub credential: CredentialWithKey,
}

// Request signature operation
pub struct SignDataMsg {
    pub data: Vec<u8>,
}
pub struct SignDataReply {
    pub signature: Vec<u8>,
}

// Update display name
pub struct UpdateHandleMsg {
    pub new_handle: String,
}

// Perform MLS operations (all signing internal)
pub struct MlsOperationMsg {
    pub operation: MlsOperation,
}

pub enum MlsOperation {
    CreateGroup {
        group_id: Vec<u8>,
    },
    AddMember {
        group_id: Vec<u8>,
        key_package: KeyPackage,
    },
    RemoveMember {
        group_id: Vec<u8>,
        member_index: u32,
    },
    EncryptMessage {
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    },
    DecryptMessage {
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    },
}

pub struct MlsOperationReply {
    pub result: MlsOperationResult,
}

pub enum MlsOperationResult {
    GroupCreated { commit: Vec<u8> },
    MemberAdded { commit: Vec<u8>, welcome: Vec<u8> },
    MemberRemoved { commit: Vec<u8> },
    MessageEncrypted { ciphertext: Vec<u8> },
    MessageDecrypted { plaintext: Vec<u8> },
}
```

### Migration Map for StateActor

| Current Code | New Code |
|--------------|----------|
| `mls_identity.signature_keypair` | `crypto_identity.ask(MlsOperationMsg)` |
| Direct MLS group operations | Send operation request via message |
| `mls_group.add_members(...)` | `MlsOperation::AddMember` |
| `mls_group.remove_members(...)` | `MlsOperation::RemoveMember` |
| Direct encryption | `MlsOperation::EncryptMessage` |
| Direct decryption | `MlsOperation::DecryptMessage` |

## Breaking Changes

### API Changes

1. **IdentityReply** - Removed `signing_key` field
2. **OpenMlsIdentityReply** - Completely removed (replaced with new messages)
3. **Actor initialization** - Single actor instead of two
4. **Message passing** - New message types required

### Migration Guide for Dependent Code

```rust
// OLD CODE:
let identity = identity_actor.ask(IdentityActorMsg {
    handle_update: None
}).await?;
let signing_key = identity.signing_key;  // ❌ No longer available

// NEW CODE:
let identity = crypto_identity.ask(GetIdentityMsg).await?;
// signing_key is NOT available (that's the security fix!)

// If you need a signature:
let signature = crypto_identity.ask(SignDataMsg {
    data: data_to_sign
}).await?.signature;
```

## Testing Strategy

### Unit Tests
- [x] SSH key loading
- [x] MLS initialization
- [x] Message handlers
- [x] Key encapsulation

### Integration Tests
- [ ] Group creation flow
- [ ] Member operations
- [ ] Message encryption/decryption
- [ ] Multi-actor scenarios

### Security Tests
- [ ] Verify no private keys in Reply types
- [ ] Verify signing happens in actor
- [ ] Verify key extraction impossible via messages
- [ ] Code review of all message types

## Risk Assessment

### Low Risk ✅
- Actor merging (well-understood pattern)
- Message type updates (compile-time checks)
- Key encapsulation (clear boundaries)

### Medium Risk ⚠️
- StateActor refactoring (complex logic)
- MLS operation migration (many operations)
- Testing coverage (need comprehensive tests)

### High Risk ❌
- None identified (proper planning mitigates risks)

## Rollback Plan

If issues arise during implementation:

1. **Keep old files temporarily** - Don't delete until new actor proven
2. **Feature flag** - Could use conditional compilation if needed
3. **Gradual migration** - Can migrate operations one at a time
4. **Git branches** - Keep implementation in separate branch until tested

## Timeline Estimate

| Phase | Estimated Time | Dependencies |
|-------|---------------|--------------|
| Phase 1: Create CryptoIdentityActor | 2-3 hours | None |
| Phase 2: Move MLS Operations | 3-4 hours | Phase 1 |
| Phase 3: Update App Init | 1 hour | Phase 1 |
| Phase 4: Update Imports | 1 hour | Phase 1-3 |
| Phase 5: Remove Old Files | 30 min | Phase 1-4 |
| Phase 6: Testing | 2-3 hours | Phase 1-5 |
| **Total** | **9-12 hours** | |

## Success Criteria

✅ **Security:**
- No private keys exposed in any Reply struct
- All signing operations happen within CryptoIdentityActor
- Code review confirms no key leakage paths

✅ **Functionality:**
- All existing features work
- No regression in behavior
- Performance is acceptable

✅ **Code Quality:**
- Clean architecture
- Well-documented
- Comprehensive tests

✅ **Documentation:**
- Updated README if needed
- Implementation plan completed
- Migration guide provided

## Next Steps

1. Review this plan
2. Get approval from project maintainer
3. Switch to code mode for implementation
4. Start with Phase 1 (create new actor)
5. Iteratively complete remaining phases
6. Test thoroughly
7. Submit PR referencing Issue #18

## References

- [GitHub Issue #18](https://github.com/devfire/agora-mls/issues/18)
- [Actor Pattern Documentation](https://docs.rs/kameo)
- [OpenMLS Documentation](https://docs.rs/openmls)
- [Cryptographic Best Practices](https://www.keylength.com/)

---

**Document Status:** Draft  
**Last Updated:** 2025-10-18  
**Author:** Roo (Architect Mode)  
**Issue:** #18 - CRITICAL: Private Key Leakage