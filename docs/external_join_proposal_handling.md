# External Join Proposal Handling in OpenMLS

## Overview

An `ExternalJoinProposal` is part of the MLS (Messaging Layer Security) protocol that allows a party **not currently in the group** to request joining the group.

## The MLS Protocol Flow

### 1. External Party Sends Join Proposal
```
External User → Group Members: ExternalJoinProposal
```
- External user creates a proposal to join
- Sends it to existing group members
- This is processed via `process_message()`

### 2. Proposal Processing (Current Implementation)
```rust
ProcessedMessageContent::ExternalJoinProposalMessage(external_join_proposal) => {
    // OpenMLS automatically queues this proposal in the group's pending proposals
    // during process_message() call
    ProcessedMessageResult::ExternalJoinProposal
}
```

**Key Points:**
- The proposal is **automatically queued** by OpenMLS
- No manual intervention needed at this stage
- The proposal is stored in the group's internal proposal queue

### 3. Committing the Proposal (TODO - Not Yet Implemented)

An existing group member must commit the proposal:

```rust
// Pseudo-code for future implementation
fn commit_external_join_proposal(group: &mut MlsGroup, crypto_provider: &OpenMlsRustCrypto) -> Result<CommitBundle> {
    // Create commit with pending proposals
    let (commit, welcome, group_info) = group.commit_to_pending_proposals(crypto_provider)?;
    
    // Merge the commit
    group.merge_pending_commit(crypto_provider)?;
    
    Ok(CommitBundle {
        commit,
        welcome,
        group_info,
    })
}
```

### 4. Send Welcome to External Joiner
```
Group Member → External Joiner: Welcome Message
```
- The Welcome message contains the group state
- External joiner uses it to join the group via `MlsGroup::new_from_welcome()`

## Implementation Status

### ✅ Completed
- [x] Process and acknowledge `ExternalJoinProposalMessage`
- [x] Return `ProcessedMessageResult::ExternalJoinProposal` to caller
- [x] Added logging for external join attempts

### 🚧 TODO
- [ ] Add command to commit pending proposals (e.g., `/commit`)
- [ ] Implement proposal viewing (list pending proposals)
- [ ] Implement selective proposal commit/reject
- [ ] Add automatic Welcome message broadcasting after commit
- [ ] Handle edge cases:
  - Multiple pending external join proposals
  - Proposal expiration
  - Conflicting proposals

## OpenMLS API Reference

### Key Types

1. **`ProcessedMessageContent::ExternalJoinProposalMessage`**
   - Contains: `QueuedProposal`
   - Automatically queued by OpenMLS
   - Retrieved via `proposal()` method

2. **`MlsGroup::commit_to_pending_proposals()`**
   - Commits all pending proposals
   - Returns: `(MlsMessageOut, Welcome, Option<GroupInfo>)`
   - Must be followed by `merge_pending_commit()`

3. **`MlsGroup::pending_proposals()`**
   - Returns iterator over pending proposals
   - Useful for viewing before committing

### Example: Full External Join Flow

```rust
// Step 1: Receive External Join Proposal
let processed = group.process_message(crypto_provider, mls_message_in)?;
match processed.into_content() {
    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
        println!("External join proposal received and queued");
        // Proposal is now in group.pending_proposals()
    }
    _ => {}
}

// Step 2: View Pending Proposals (Optional)
for proposal in group.pending_proposals() {
    println!("Pending proposal: {:?}", proposal);
}

// Step 3: Commit Proposals (requires group admin/member)
let (commit, welcome, group_info) = group.commit_to_pending_proposals(crypto_provider)?;
group.merge_pending_commit(crypto_provider)?;

// Step 4: Broadcast commit to all group members
broadcast(commit);

// Step 5: Send welcome to external joiner
send_to_joiner(welcome);
```

## Current Handler Implementation

Location: [`src/crypto_identity_actor.rs:478-493`](src/crypto_identity_actor.rs:478-493)

```rust
ProcessedMessageContent::ExternalJoinProposalMessage(external_join_proposal) => {
    // The proposal has been automatically added to the group's proposal queue
    // by OpenMLS during process_message(). An existing group member needs to
    // commit this proposal to complete the external join.
    
    // Log the external join attempt for visibility
    tracing::info!(
        "External join proposal received in group: {:?}. Proposal queued for commit.",
        group.group_id()
    );
    
    // Store proposal reference if needed for tracking
    // Note: OpenMLS handles the proposal queue internally
    let _proposal_ref = external_join_proposal.proposal();
    
    ProcessedMessageResult::ExternalJoinProposal
}
```

## Next Steps

1. **Add `/proposals` command** to view pending proposals
2. **Add `/commit` command** to commit pending proposals
3. **Implement automatic Welcome broadcasting** after successful commit
4. **Add proposal rejection** capability if needed
5. **Update processor.rs** to handle `ProcessedMessageResult::ExternalJoinProposal` properly

## Security Considerations

- External join proposals allow **anyone** to request joining
- Group policy determines if proposals are automatically accepted
- Current implementation: proposals are queued, not auto-accepted
- Manual commit provides control over who joins

## References

- [OpenMLS Documentation](https://openmls.tech)
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- OpenMLS API: `MlsGroup::commit_to_pending_proposals()`
- OpenMLS API: `ProcessedMessage::into_content()`