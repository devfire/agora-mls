# Phase 2 Architecture: Complete Private Key Encapsulation

**Goal:** Eliminate `signature_keypair` exposure from [`CryptoIdentityReply::MlsIdentity`](../src/crypto_identity_actor.rs:63) by moving all MLS operations into [`CryptoIdentityActor`](../src/crypto_identity_actor.rs:1).

## Current Architecture Issues

### StateActor Responsibilities (TOO MANY)
```rust
pub struct StateActor {
    groups: HashMap<String, MlsGroup>,  // ❌ Requires signature_keypair for operations
    active_group: Option<String>,
    crypto_identity: ActorRef<CryptoIdentityActor>,
    key_packages: HashMap<String, KeyPackageIn>,
}
```

### MLS Operations in StateActor (Lines with signature_keypair access)
1. **Line 254-260**: `add_members()` - Requires signature_keypair
2. **Line 263**: `merge_pending_commit()` - Requires crypto_provider
3. **Line 305**: `create_message()` - Requires signature_keypair
4. **Line 380-402**: `process_message()` + `merge_staged_commit()` - Requires crypto_provider
5. **Line 428-450**: `process_message()` (Private) + `merge_staged_commit()`
6. **Line 626-630**: `MlsGroup::new()` - Requires signature_keypair
7. **Line 505**: `into_group()` from Welcome - Requires crypto_provider

## Proposed Phase 2 Architecture

### 🎯 New Responsibility Division

```
┌─────────────────────────────────────────────────┐
│         StateActor (Coordinator)                │
│  • Manages application state                    │
│  • Tracks active group name                     │
│  • Stores user key packages                     │
│  • Routes commands to CryptoIdentityActor       │
│  • NO ACCESS to signature_keypair ✅            │
└─────────────────────────────────────────────────┘
                     │
                     │ Sends operation requests
                     ▼
┌─────────────────────────────────────────────────┐
│      CryptoIdentityActor (MLS Engine)           │
│  • Stores MLS groups (HashMap<String, MlsGroup>)│
│  • Performs ALL MLS operations internally       │
│  • Uses signature_keypair for signing           │
│  • Returns only operation results               │
│  • Private keys NEVER exposed ✅                │
└─────────────────────────────────────────────────┘
```

### 📝 New Message Types for CryptoIdentityActor

Add to `CryptoIdentityMessage` enum:

```rust
pub enum CryptoIdentityMessage {
    // Existing messages...
    GetIdentity,
    GetKeyPackage,
    SignData { data: Vec<u8> },
    UpdateHandle { new_handle: String },
    
    // NEW MLS Operation Messages
    CreateGroup {
        group_name: String,
    },
    AddMember {
        group_name: String,
        key_package: KeyPackage,
    },
    EncryptMessage {
        group_name: String,
        plaintext: Vec<u8>,
    },
    ProcessMessage {
        group_name: String,
        mls_message: MlsMessageIn,
    },
    JoinGroup {
        welcome: Welcome,
    },
    ListGroups,
    GetActiveGroup,
    SetActiveGroup {
        group_name: String,
    },
}
```

Add to `CryptoIdentityReply` enum:

```rust
pub enum CryptoIdentityReply {
    // Existing replies...
    Identity { handle, verifying_key },
    KeyPackage { key_package, credential },
    Signature { signature },
    UpdateComplete,
    
    // NEW MLS Operation Replies
    GroupCreated {
        group_name: String,
    },
    MemberAdded {
        commit: MlsMessageOut,
        welcome: Welcome,
        group_info: Option<GroupInfo>,
    },
    MessageEncrypted {
        ciphertext: MlsMessageOut,
    },
    MessageProcessed {
        result: ProcessedMessageResult,
    },
    GroupJoined {
        group_name: String,
    },
    Groups {
        groups: Vec<String>,
    },
    ActiveGroup {
        group_name: Option<String>,
    },
    Success,
}

pub enum ProcessedMessageResult {
    ApplicationMessage(String),  // Decrypted text
    ProposalMessage,
    ExternalJoinProposal,
    StagedCommitMerged,
}
```

### 🏗️ CryptoIdentityActor Internal State

```rust
#[derive(Actor)]
pub struct CryptoIdentityActor {
    // SSH Identity (PRIVATE)
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    handle: String,
    
    // MLS Protocol State (PRIVATE)
    ciphersuite: Ciphersuite,
    signature_algorithm: SignatureScheme,
    mls_key_package: KeyPackageBundle,
    credential_with_key: CredentialWithKey,
    signature_keypair: Arc<SignatureKeyPair>,
    crypto_provider: Arc<OpenMlsRustCrypto>,
    
    // NEW: MLS Group Management (MOVED from StateActor)
    groups: HashMap<String, MlsGroup>,
    active_group: Option<String>,
}
```

### 🔄 StateActor Simplified State

```rust
#[derive(Actor)]
pub struct StateActor {
    crypto_identity: ActorRef<CryptoIdentityActor>,
    key_packages: HashMap<String, KeyPackageIn>,  // Still needed for user discovery
    // groups and active_group REMOVED - now in CryptoIdentityActor
}
```

## Implementation Plan

### Step 1: Add MLS State to CryptoIdentityActor

```rust
impl CryptoIdentityActor {
    pub fn new(key_file_path: &Path, display_name: &str) -> Result<Self> {
        // ... existing initialization ...
        
        Ok(CryptoIdentityActor {
            // ... existing fields ...
            groups: HashMap::new(),         // NEW
            active_group: None,             // NEW
        })
    }
}
```

### Step 2: Add MLS Operation Handlers

```rust
impl Message<CryptoIdentityMessage> for CryptoIdentityActor {
    type Reply = CryptoIdentityReply;
    
    async fn handle(&mut self, msg: CryptoIdentityMessage, _ctx: Context) -> Self::Reply {
        match msg {
            // Existing handlers...
            
            CryptoIdentityMessage::CreateGroup { group_name } => {
                self.handle_create_group(group_name)
            }
            
            CryptoIdentityMessage::AddMember { group_name, key_package } => {
                self.handle_add_member(group_name, key_package)
            }
            
            CryptoIdentityMessage::EncryptMessage { group_name, plaintext } => {
                self.handle_encrypt_message(group_name, plaintext)
            }
            
            CryptoIdentityMessage::ProcessMessage { group_name, mls_message } => {
                self.handle_process_message(group_name, mls_message)
            }
            
            CryptoIdentityMessage::JoinGroup { welcome } => {
                self.handle_join_group(welcome)
            }
            
            CryptoIdentityMessage::ListGroups => {
                CryptoIdentityReply::Groups {
                    groups: self.groups.keys().cloned().collect()
                }
            }
            
            CryptoIdentityMessage::GetActiveGroup => {
                CryptoIdentityReply::ActiveGroup {
                    group_name: self.active_group.clone()
                }
            }
            
            CryptoIdentityMessage::SetActiveGroup { group_name } => {
                if self.groups.contains_key(&group_name) {
                    self.active_group = Some(group_name);
                    CryptoIdentityReply::Success
                } else {
                    // Return error via reply enum
                    CryptoIdentityReply::Error(...)
                }
            }
        }
    }
}

impl CryptoIdentityActor {
    fn handle_create_group(&mut self, group_name: String) -> CryptoIdentityReply {
        // All MLS group creation logic here
        // Uses self.signature_keypair internally
        // Returns only CryptoIdentityReply::GroupCreated
    }
    
    fn handle_add_member(&mut self, group_name: String, key_package: KeyPackage) 
        -> CryptoIdentityReply 
    {
        // Get group
        // Call add_members with self.signature_keypair
        // Call merge_pending_commit
        // Return commit and welcome messages
    }
    
    fn handle_encrypt_message(&mut self, group_name: String, plaintext: Vec<u8>) 
        -> CryptoIdentityReply 
    {
        // Get group
        // Call create_message with self.signature_keypair
        // Return encrypted message
    }
    
    fn handle_process_message(&mut self, group_name: String, mls_message: MlsMessageIn) 
        -> CryptoIdentityReply 
    {
        // Get group
        // Call process_message with self.crypto_provider
        // Handle different message types
        // Merge commits if needed
        // Return result
    }
    
    fn handle_join_group(&mut self, welcome: Welcome) -> CryptoIdentityReply {
        // Stage welcome
        // Convert to group
        // Extract group name
        // Store group
        // Return success with group name
    }
}
```

### Step 3: Update StateActor to Delegate

**Command::Create:**
```rust
// OLD:
self.create_mls_group(&name).await?;

// NEW:
let reply = self.crypto_identity.ask(CryptoIdentityMessage::CreateGroup {
    group_name: name.clone()
}).await?;

match reply {
    CryptoIdentityReply::GroupCreated { .. } => {
        Ok(StateActorReply::Success("Group created".to_string()))
    }
    _ => Err(StateActorError::EncryptionFailed),
}
```

**Command::Invite:**
```rust
// OLD:
let mls_group_ref = self.groups.get_mut(current_group_name)?;
let (commit, welcome, _) = mls_group_ref.add_members(...)?;

// NEW:
let reply = self.crypto_identity.ask(CryptoIdentityMessage::AddMember {
    group_name: current_group_name.clone(),
    key_package: validated_key_package,
}).await?;

match reply {
    CryptoIdentityReply::MemberAdded { commit, welcome, .. } => {
        // Create protobuf messages
        // Return for network transmission
    }
    _ => Err(StateActorError::EncryptionFailed),
}
```

**StateActorMessage::Encrypt:**
```rust
// OLD:
let mls_group_ref = self.groups.get_mut(active_group_name)?;
let ciphertext = mls_group_ref.create_message(...)?;

// NEW:
let reply = self.crypto_identity.ask(CryptoIdentityMessage::EncryptMessage {
    group_name: active_group_name.clone(),
    plaintext: plaintext_payload.encode_to_vec(),
}).await?;

match reply {
    CryptoIdentityReply::MessageEncrypted { ciphertext } => {
        Ok(StateActorReply::MlsMessageOut(vec![ciphertext.try_into()?]))
    }
    _ => Err(StateActorError::EncryptionFailed),
}
```

**StateActorMessage::Decrypt:**
```rust
// OLD:
let mls_group_ref = self.groups.get_mut(active_group_name)?;
let processed = mls_group_ref.process_message(...)?;

// NEW:
let reply = self.crypto_identity.ask(CryptoIdentityMessage::ProcessMessage {
    group_name: active_group_name.clone(),
    mls_message: proto_in,
}).await?;

match reply {
    CryptoIdentityReply::MessageProcessed { result } => {
        match result {
            ProcessedMessageResult::ApplicationMessage(text) => {
                Ok(StateActorReply::DecryptedMessage(text))
            }
            ProcessedMessageResult::StagedCommitMerged => {
                Ok(StateActorReply::Success("Commit merged".to_string()))
            }
            // Handle other cases
        }
    }
    _ => Err(StateActorError::DecryptionFailed),
}
```

### Step 4: Remove Obsolete Code

**From StateActor:**
- Remove `groups: HashMap<String, MlsGroup>` field
- Remove `active_group: Option<String>` field (query CryptoIdentityActor instead)
- Remove `create_mls_group()` method
- Remove `get_group_name()` method
- Update all group-related operations to delegate

**From CryptoIdentityActor:**
- Remove `signature_keypair` from `MlsIdentity` reply variant
- Remove the TODO comments about temporary exposure

## Benefits of Phase 2

### ✅ Security
- **Complete Key Encapsulation**: `signature_keypair` NEVER leaves [`CryptoIdentityActor`](../src/crypto_identity_actor.rs:1)
- **No Exposure in Messages**: All replies contain only operation results
- **Atomic Operations**: All MLS operations happen in one secure context

### ✅ Architecture
- **Clear Separation**: StateActor = coordinator, CryptoIdentityActor = crypto engine
- **Single Responsibility**: Each actor has one clear purpose
- **Testability**: Can test MLS operations independently

### ✅ Maintainability
- **Centralized Crypto**: All crypto operations in one place
- **Easier to Audit**: Security-critical code in one actor
- **Future-Proof**: Easy to add new MLS operations

## Migration Complexity

### High Effort Areas
1. **Moving MLS State** (groups HashMap) - Moderate complexity
2. **Implementing Operation Handlers** - High complexity (7 operations)
3. **Updating StateActor** - High complexity (touches many commands)
4. **Testing** - High complexity (verify all operations still work)

### Estimated Effort
- **Design**: 1 hour (THIS DOCUMENT)
- **Implementation**: 4-6 hours
- **Testing**: 2-3 hours
- **Total**: 7-10 hours

## Rollout Strategy

### Option A: Big Bang (Recommended for small codebase)
1. Implement all changes in one PR
2. Test comprehensively before merge
3. Deploy together

### Option B: Incremental
1. Phase 2a: Add MLS state to CryptoIdentityActor (keep both)
2. Phase 2b: Add operation handlers
3. Phase 2c: Migrate one operation at a time
4. Phase 2d: Remove old code

### Recommendation
**Option A (Big Bang)** - The codebase is small enough that incremental migration adds more complexity than value.

## Testing Strategy

### Unit Tests
- Test each MLS operation handler in [`CryptoIdentityActor`](../src/crypto_identity_actor.rs:1)
- Verify message flow for each operation
- Confirm signature_keypair never appears in replies

### Integration Tests
- Create group → verify group exists
- Add member → verify commit and welcome generated
- Encrypt message → decrypt message → verify plaintext
- Process Welcome → verify group joined

### Security Tests
- Code audit: Verify no `signature_keypair` in any Reply type
- Message inspection: Capture and verify reply contents
- Attempted key extraction: Verify impossible via messages

## Acceptance Criteria

✅ **Phase 2 Complete When:**
1. All MLS operations moved to [`CryptoIdentityActor`](../src/crypto_identity_actor.rs:1)
2. `signature_keypair` removed from all Reply types
3. [`StateActor`](../src/state_actor.rs:1) successfully delegates all operations
4. All existing functionality works
5. Project compiles without warnings
6. All tests pass

## Next Steps

1. **Review this design** with stakeholders
2. **Get approval** to proceed
3. **Switch to Code mode** for implementation
4. **Implement systematically** following the plan
5. **Test thoroughly** at each step
6. **Document changes** for future maintainers

---

**Document Status:** Architecture Design  
**Phase:** 2 (Complete Key Encapsulation)  
**Estimated Effort:** 7-10 hours  
**Risk Level:** Medium (large refactor, but clear path)  
**Security Impact:** HIGH (eliminates remaining key exposure)