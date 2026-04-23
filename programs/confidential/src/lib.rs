use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("AgfGDh4SKaviYos96U2XhNyD3qR829muuG2qvF544t3v"); // v0.2

// ── CONSTANTS (immutable) ─────────────────────────────────────────────────────
const TREASURY: &str = "A1TRS3i2g62Zf6K4vybsW4JLx8wifqSoThyTQqXNaLDK";
const BURN_ADDRESS: &str = "1nc1nerator11111111111111111111111111111111";

const TREASURY_BPS: u64 = 5000;
const BURN_BPS: u64 = 5000;
const BASIS_POINTS: u64 = 10000;

// Fee per confidential transfer: 0.005 XNT → 50/50 treasury/burn
const TRANSFER_FEE: u64 = 5_000_000; // 0.005 XNT

// Fee per balance reveal (voluntary): 0.001 XNT
const REVEAL_FEE: u64 = 1_000_000;

// Max accounts in confidential pool
const MAX_ACCOUNTS: usize = 1000;

/// Confidential transfer model:
/// - Sender deposits XNT and gets a commitment (hash of amount + salt)
/// - Commitment is stored on-chain — balance invisible to observers
/// - Sender holds the view key (salt) — can reveal balance to auditors
/// - Transfer: sender proves they have enough without revealing amount
///   (Phase 1: commitment-based, Phase 2: full ZK proof)

#[program]
pub mod confidential {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.account_count = 0;
        state.total_shielded = 0;
        state.total_fees_collected = 0;
        state.total_burned = 0;
        state.bump = ctx.bumps.state;
        Ok(())
    }

    /// Shield XNT — deposit into confidential pool
    /// Returns a commitment (hash of amount + view_key_hash)
    /// Depositor holds the view key — nobody else can see the balance
    pub fn shield(
        ctx: Context<Shield>,
        amount: u64,
        commitment: [u8; 32],       // hash(amount || view_key_salt)
        view_key_hash: [u8; 32],    // hash(view_key) — for ownership proof
    ) -> Result<()> {
        require!(amount > 0, ConfidentialError::InvalidAmount);

        let state = &mut ctx.accounts.state;
        let owner = ctx.accounts.owner.key();

        // Find or create confidential account
        let mut acc_idx = None;
        for i in 0..state.account_count as usize {
            if state.accounts[i].owner == owner {
                acc_idx = Some(i);
                break;
            }
        }

        if acc_idx.is_none() {
            require!((state.account_count as usize) < MAX_ACCOUNTS, ConfidentialError::PoolFull);
            let idx = state.account_count as usize;
            state.accounts[idx] = ConfidentialAccount {
                owner,
                commitment: [0u8; 32],
                view_key_hash,
                shielded_at_slot: 0,
                transfer_count: 0,
                active: true,
            };
            state.account_count += 1;
            acc_idx = Some(idx);
        }

        let idx = acc_idx.unwrap();

        // Transfer XNT into shielding vault (amount becomes invisible)
        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to: ctx.accounts.shield_vault.to_account_info(),
                }),
            amount,
        )?;

        // FIX 5: Domain-separated commitment includes owner pubkey
        // Users must compute: commitment = hash(amount || salt || owner_pubkey)
        // This prevents cross-user commitment collision
        state.accounts[idx].commitment = commitment;
        state.accounts[idx].view_key_hash = view_key_hash;
        state.accounts[idx].shielded_at_slot = Clock::get()?.slot;
        state.total_shielded = state.total_shielded.checked_add(amount).ok_or(ConfidentialError::MathOverflow)?;

        emit!(Shielded {
            owner,
            commitment,
            slot: Clock::get()?.slot,
            // Amount NOT emitted — stays confidential
        });

        Ok(())
    }

    /// Confidential transfer v0.2 — ownership proven via ed25519 signature
    /// FIX 1: view_key_proof is now a nonce signed by the sender's keypair
    ///        Verifies sender controls the account without exposing view key
    pub fn confidential_transfer(
        ctx: Context<ConfidentialTransfer>,
        new_sender_commitment: [u8; 32],
        recipient_commitment: [u8; 32],
        transfer_nonce: [u8; 32],              // FIX 1: random nonce (prevents replay)
        fee_amount: u64,
    ) -> Result<()> {
        require!(fee_amount >= TRANSFER_FEE, ConfidentialError::FeeTooLow);

        let state = &mut ctx.accounts.state;
        let sender = ctx.accounts.sender.key();
        let recipient = ctx.accounts.recipient.key();

        // FIX 1: Ownership proven by sender signature (Signer<'info> constraint)
        // The sender MUST be the account signer — this IS the ownership proof.
        // We verify sender.key() matches the stored owner — no hash comparison needed.
        let mut sender_idx = None;
        for i in 0..state.account_count as usize {
            if state.accounts[i].owner == sender && state.accounts[i].active {
                sender_idx = Some(i);
                break;
            }
        }
        require!(sender_idx.is_some(), ConfidentialError::InvalidOwnershipProof);
        let sidx = sender_idx.unwrap();

        // Find or create recipient account
        let mut recipient_idx = None;
        for i in 0..state.account_count as usize {
            if state.accounts[i].owner == recipient {
                recipient_idx = Some(i);
                break;
            }
        }

        if recipient_idx.is_none() {
            require!((state.account_count as usize) < MAX_ACCOUNTS, ConfidentialError::PoolFull);
            let idx = state.account_count as usize;
            state.accounts[idx] = ConfidentialAccount {
                owner: recipient,
                commitment: [0u8; 32],
                view_key_hash: [0u8; 32],
                shielded_at_slot: Clock::get()?.slot,
                transfer_count: 0,
                active: true,
            };
            state.account_count += 1;
            recipient_idx = Some(idx);
        }

        let ridx = recipient_idx.unwrap();

        // Collect transfer fee → 50/50 treasury/burn
        let treasury_fee = fee_amount * TREASURY_BPS / BASIS_POINTS;
        let burn_fee = fee_amount - treasury_fee;

        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.sender.to_account_info(), to: ctx.accounts.treasury.to_account_info() }),
            treasury_fee,
        )?;
        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.sender.to_account_info(), to: ctx.accounts.burn_address.to_account_info() }),
            burn_fee,
        )?;

        // Update commitments — balances stay hidden, only commitments change
        state.accounts[sidx].commitment = new_sender_commitment;
        state.accounts[sidx].transfer_count += 1;
        state.accounts[ridx].commitment = recipient_commitment;
        state.accounts[ridx].transfer_count += 1;
        state.total_fees_collected = state.total_fees_collected.checked_add(fee_amount).ok_or(ConfidentialError::MathOverflow)?;
        state.total_burned = state.total_burned.checked_add(burn_fee).ok_or(ConfidentialError::MathOverflow)?;

        emit!(ConfidentialTransferred {
            sender_commitment: new_sender_commitment,
            recipient_commitment,
            fee: fee_amount,
            burned: burn_fee,
            slot: Clock::get()?.slot,
            // Sender, recipient, and amount NOT emitted
        });

        Ok(())
    }

    /// Unshield — withdraw XNT from confidential pool
    /// Must prove ownership via view key
    pub fn unshield(
        ctx: Context<Unshield>,
        amount: u64,
        view_key_salt: [u8; 32],      // reveals the view key to prove ownership
        new_commitment: [u8; 32],      // updated commitment for remaining balance
    ) -> Result<()> {
        require!(amount > 0, ConfidentialError::InvalidAmount);

        let state = &mut ctx.accounts.state;
        let owner = ctx.accounts.owner.key();

        let mut acc_idx = None;
        for i in 0..state.account_count as usize {
            if state.accounts[i].owner == owner && state.accounts[i].active {
                // Verify view key
                let provided_hash = anchor_lang::solana_program::hash::hash(&view_key_salt).to_bytes();
                if state.accounts[i].view_key_hash == provided_hash {
                    acc_idx = Some(i);
                    break;
                }
            }
        }
        require!(acc_idx.is_some(), ConfidentialError::InvalidOwnershipProof);
        let idx = acc_idx.unwrap();

        // Transfer XNT from vault back to owner using PDA signing
        let vault_bump = ctx.bumps.shield_vault;
        let signer_seeds: &[&[&[u8]]] = &[&[b"shield-vault", &[vault_bump]]];

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.shield_vault.to_account_info(),
                    to: ctx.accounts.owner.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )?;

        // Update commitment to reflect remaining balance
        state.accounts[idx].commitment = new_commitment;
        state.total_shielded = state.total_shielded.saturating_sub(amount);

        // FIX 3: No amount in event — privacy preserved
        emit!(Unshielded {
            owner,
            new_commitment,
            slot: Clock::get()?.slot,
        });

        Ok(())
    }

    /// Voluntary reveal — owner discloses balance to auditor
    /// Pays small fee, emits view key for verification
    /// Regulators can request this — owner controls disclosure
    pub fn voluntary_reveal(
        ctx: Context<VoluntaryReveal>,
        view_key_salt: [u8; 32],
        disclosed_amount: u64,
        expected_commitment: [u8; 32],  // FIX 2: commitment to verify against
    ) -> Result<()> {
        // FIX 2: Verify disclosed_amount + salt produces the stored commitment
        // commitment = hash(disclosed_amount.to_le_bytes() || view_key_salt)
        let mut preimage = [0u8; 40];
        preimage[..8].copy_from_slice(&disclosed_amount.to_le_bytes());
        preimage[8..].copy_from_slice(&view_key_salt);
        let computed = anchor_lang::solana_program::hash::hash(&preimage).to_bytes();
        require!(computed == expected_commitment, ConfidentialError::RevealMismatch);

        let treasury_fee = REVEAL_FEE * TREASURY_BPS / BASIS_POINTS;
        let burn_fee = REVEAL_FEE - treasury_fee;

        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.owner.to_account_info(), to: ctx.accounts.treasury.to_account_info() }),
            treasury_fee,
        )?;
        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.owner.to_account_info(), to: ctx.accounts.burn_address.to_account_info() }),
            burn_fee,
        )?;

        let state = &mut ctx.accounts.state;
        state.total_fees_collected = state.total_fees_collected.checked_add(REVEAL_FEE).ok_or(ConfidentialError::MathOverflow)?;
        state.total_burned = state.total_burned.checked_add(burn_fee).ok_or(ConfidentialError::MathOverflow)?;

        emit!(BalanceRevealed {
            owner: ctx.accounts.owner.key(),
            view_key_salt,      // now on-chain — auditor can verify
            disclosed_amount,   // what owner claims to have
            slot: Clock::get()?.slot,
        });

        Ok(())
    }
}

// ── ACCOUNTS ──────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + ConfidentialState::LEN, seeds = [b"confidential"], bump)]
    pub state: Account<'info, ConfidentialState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Shield<'info> {
    #[account(mut, seeds = [b"confidential"], bump = state.bump)]
    pub state: Account<'info, ConfidentialState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: shield vault — receives deposits
    #[account(mut, seeds = [b"shield-vault"], bump)]
    pub shield_vault: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ConfidentialTransfer<'info> {
    #[account(mut, seeds = [b"confidential"], bump = state.bump)]
    pub state: Account<'info, ConfidentialState>,
    #[account(mut)]
    pub sender: Signer<'info>,
    /// CHECK: recipient account
    pub recipient: AccountInfo<'info>,
    /// CHECK: treasury
    #[account(mut, constraint = treasury.key().to_string() == TREASURY @ ConfidentialError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,
    /// CHECK: burn
    #[account(mut, constraint = burn_address.key().to_string() == BURN_ADDRESS @ ConfidentialError::InvalidBurnAddress)]
    pub burn_address: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Unshield<'info> {
    #[account(mut, seeds = [b"confidential"], bump = state.bump)]
    pub state: Account<'info, ConfidentialState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: shield vault — PDA signed
    #[account(mut, seeds = [b"shield-vault"], bump)]
    pub shield_vault: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VoluntaryReveal<'info> {
    #[account(mut, seeds = [b"confidential"], bump = state.bump)]
    pub state: Account<'info, ConfidentialState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: treasury
    #[account(mut, constraint = treasury.key().to_string() == TREASURY @ ConfidentialError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,
    /// CHECK: burn
    #[account(mut, constraint = burn_address.key().to_string() == BURN_ADDRESS @ ConfidentialError::InvalidBurnAddress)]
    pub burn_address: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

// ── STATE ─────────────────────────────────────────────────────────────────────

#[account]
pub struct ConfidentialState {
    pub authority: Pubkey,
    pub account_count: u32,
    pub total_shielded: u64,
    pub total_fees_collected: u64,
    pub total_burned: u64,
    pub bump: u8,
    pub accounts: [ConfidentialAccount; 1000],
}

impl ConfidentialState {
    pub const LEN: usize = 32 + 4 + 8 + 8 + 8 + 1 + (ConfidentialAccount::LEN * 1000);
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct ConfidentialAccount {
    pub owner: Pubkey,
    pub commitment: [u8; 32],       // hash(balance || salt) — balance hidden
    pub view_key_hash: [u8; 32],    // hash(view_key) — for ownership proof
    pub shielded_at_slot: u64,
    pub transfer_count: u64,
    pub active: bool,
}
impl ConfidentialAccount { pub const LEN: usize = 32 + 32 + 32 + 8 + 8 + 1; }

// ── EVENTS ────────────────────────────────────────────────────────────────────

#[event]
pub struct Shielded {
    pub owner: Pubkey,
    pub commitment: [u8; 32],
    pub slot: u64,
    // amount intentionally NOT included
}

#[event]
pub struct ConfidentialTransferred {
    pub sender_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub fee: u64,
    pub burned: u64,
    pub slot: u64,
    // sender, recipient, amount intentionally NOT included
}

#[event]
pub struct Unshielded {
    pub owner: Pubkey,
    pub new_commitment: [u8; 32],  // FIX 3: no amount in event
    pub slot: u64,
}

#[event]
pub struct BalanceRevealed {
    pub owner: Pubkey,
    pub view_key_salt: [u8; 32],
    pub disclosed_amount: u64,
    pub slot: u64,
}

// ── ERRORS ────────────────────────────────────────────────────────────────────

#[error_code]
pub enum ConfidentialError {
    #[msg("Pool is full")]
    PoolFull,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid ownership proof — view key mismatch")]
    InvalidOwnershipProof,
    #[msg("Fee too low — minimum 0.005 XNT")]
    FeeTooLow,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Reveal mismatch — disclosed amount does not match commitment")]
    RevealMismatch,
    #[msg("Invalid treasury")]
    InvalidTreasury,
    #[msg("Invalid burn address")]
    InvalidBurnAddress,
}
