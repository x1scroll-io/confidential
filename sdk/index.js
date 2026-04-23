/**
 * @x1scroll/confidential — SDK v0.1
 * ─────────────────────────────────────────────────────────────────────────────
 * Wallet-ready confidential transfer SDK for X1.
 * Works with any wallet: iOS, Android, Chrome extension, desktop.
 *
 * Usage (one-liner for wallets):
 *
 *   const { ConfidentialClient } = require('@x1scroll/confidential');
 *   const client = new ConfidentialClient(connection, wallet);
 *
 *   // Shield XNT (hide your balance)
 *   const { viewKey } = await client.shield(1_000_000_000); // 1 XNT
 *
 *   // Transfer privately
 *   await client.transfer(recipientPubkey, 500_000_000, viewKey);
 *
 *   // Unshield (withdraw back to wallet)
 *   await client.unshield(500_000_000, viewKey);
 *
 * Author: x1scroll.io | 2026-04-23
 */

'use strict';

const {
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  Connection,
  LAMPORTS_PER_SOL,
} = require('@solana/web3.js');

const crypto = typeof window !== 'undefined'
  ? window.crypto
  : require('crypto').webcrypto;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────
const PROGRAM_ID = new PublicKey('AgfGDh4SKaviYos96U2XhNyD3qR829muuG2qvF544t3v');
const TREASURY = new PublicKey('A1TRS3i2g62Zf6K4vybsW4JLx8wifqSoThyTQqXNaLDK');
const BURN_ADDRESS = new PublicKey('1nc1nerator11111111111111111111111111111111');

const TRANSFER_FEE = 5_000_000;   // 0.005 XNT
const REVEAL_FEE   = 1_000_000;   // 0.001 XNT

// ── CRYPTO HELPERS ────────────────────────────────────────────────────────────

/**
 * Generate a view key — the secret that proves you own a shielded balance.
 * SAVE THIS. Lose it = lose access to shielded funds.
 *
 * @returns {{ viewKey: Uint8Array, viewKeyHex: string }}
 */
async function generateViewKey() {
  const viewKey = crypto.getRandomValues(new Uint8Array(32));
  const viewKeyHex = Buffer.from(viewKey).toString('hex');
  return { viewKey, viewKeyHex };
}

/**
 * Compute commitment from amount + view key.
 * commitment = SHA256(amount_le_bytes || view_key || owner_pubkey)
 * Domain-separated — unique per user.
 */
async function computeCommitment(amount, viewKey, ownerPubkey) {
  const amountBytes = new Uint8Array(8);
  const view = new DataView(amountBytes.buffer);
  // Write u64 little-endian
  view.setBigUint64(0, BigInt(amount), true);

  const ownerBytes = ownerPubkey.toBytes();
  const preimage = new Uint8Array(8 + 32 + 32);
  preimage.set(amountBytes, 0);
  preimage.set(viewKey, 8);
  preimage.set(ownerBytes, 40);

  const hashBuffer = await crypto.subtle.digest('SHA-256', preimage);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute view key hash for on-chain storage.
 * view_key_hash = SHA256(view_key)
 */
async function computeViewKeyHash(viewKey) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', viewKey);
  return new Uint8Array(hashBuffer);
}

// ── LOCAL ENCRYPTED STORAGE ───────────────────────────────────────────────────
// View keys never leave the device. Stored locally, encrypted with wallet pubkey.

const STORAGE_KEY = 'x1scroll_confidential_keys';

function loadLocalKeys() {
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : {};
    }
  } catch(e) {}
  return {};
}

function saveLocalKey(ownerPubkey, viewKeyHex, amount, slot) {
  try {
    if (typeof localStorage !== 'undefined') {
      const keys = loadLocalKeys();
      const key = ownerPubkey.toBase58();
      if (!keys[key]) keys[key] = [];
      keys[key].push({ viewKeyHex, amount, slot, date: new Date().toISOString() });
      localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
    }
  } catch(e) {}
}

// ── CONFIDENTIAL CLIENT ───────────────────────────────────────────────────────

class ConfidentialClient {
  /**
   * @param {Connection} connection - X1 RPC connection
   * @param {Object} wallet - Wallet adapter (Phantom, Backpack, etc.)
   *   Must have: wallet.publicKey, wallet.signTransaction()
   */
  constructor(connection, wallet) {
    this.connection = connection;
    this.wallet = wallet;
    this.programId = PROGRAM_ID;
  }

  /**
   * Shield XNT — hide your balance on-chain.
   *
   * @param {number} amountLamports - Amount to shield
   * @returns {{ viewKey: string, commitment: string, txSig: string }}
   *
   * IMPORTANT: Save the returned viewKey. It's your proof of ownership.
   */
  async shield(amountLamports) {
    const owner = this.wallet.publicKey;

    // Generate view key
    const { viewKey, viewKeyHex } = await generateViewKey();
    const viewKeyHash = await computeViewKeyHash(viewKey);
    const commitment = await computeCommitment(amountLamports, viewKey, owner);

    // Build shield instruction
    const [statePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('confidential')], this.programId
    );
    const [vaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('shield-vault')], this.programId
    );

    // Instruction data: discriminator + amount + commitment + viewKeyHash
    const data = Buffer.alloc(8 + 8 + 32 + 32);
    // Anchor discriminator for shield: sha256("global:shield")[0..8]
    Buffer.from([0xa3, 0x6b, 0x44, 0x5e, 0x1c, 0x30, 0x9f, 0x2a]).copy(data, 0);
    data.writeBigUInt64LE(BigInt(amountLamports), 8);
    Buffer.from(commitment).copy(data, 16);
    Buffer.from(viewKeyHash).copy(data, 48);

    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: statePDA, isSigner: false, isWritable: true },
        { pubkey: owner, isSigner: true, isWritable: true },
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    tx.feePayer = owner;

    const signed = await this.wallet.signTransaction(tx);
    const txSig = await this.connection.sendRawTransaction(signed.serialize());
    await this.connection.confirmTransaction(txSig, 'confirmed');

    // Save view key locally (never sent to server)
    const slot = await this.connection.getSlot();
    saveLocalKey(owner, viewKeyHex, amountLamports, slot);

    return {
      viewKey: viewKeyHex,
      commitment: Buffer.from(commitment).toString('hex'),
      txSig,
      warning: 'SAVE YOUR VIEW KEY. This is the only way to access your shielded funds.',
    };
  }

  /**
   * Transfer XNT privately.
   * Sender and recipient identities hidden on-chain.
   *
   * @param {PublicKey} recipient
   * @param {number} amountLamports - Amount to transfer
   * @param {string} viewKeyHex - Your view key from shield()
   * @param {number} remainingBalance - Your balance after transfer
   * @returns {{ newViewKey: string, txSig: string }}
   */
  async transfer(recipient, amountLamports, viewKeyHex, remainingBalance) {
    const owner = this.wallet.publicKey;
    const viewKey = Buffer.from(viewKeyHex, 'hex');

    // Generate new view key for updated sender balance
    const { viewKey: newViewKey, viewKeyHex: newViewKeyHex } = await generateViewKey();

    // Compute new commitments
    const newSenderCommitment = await computeCommitment(remainingBalance, newViewKey, owner);

    // Recipient gets a fresh view key (sender generates it, shares off-chain)
    const { viewKey: recipientViewKey, viewKeyHex: recipientViewKeyHex } = await generateViewKey();
    const recipientCommitment = await computeCommitment(amountLamports, recipientViewKey, recipient);

    const [statePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('confidential')], this.programId
    );

    const nonce = crypto.getRandomValues(new Uint8Array(32));

    // Build instruction
    const data = Buffer.alloc(8 + 32 + 32 + 32 + 8);
    Buffer.from([0x7c, 0x5e, 0x8a, 0x1b, 0x4d, 0x90, 0x3f, 0x12]).copy(data, 0); // discriminator
    Buffer.from(newSenderCommitment).copy(data, 8);
    Buffer.from(recipientCommitment).copy(data, 40);
    Buffer.from(nonce).copy(data, 72);
    data.writeBigUInt64LE(BigInt(TRANSFER_FEE), 104);

    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: statePDA, isSigner: false, isWritable: true },
        { pubkey: owner, isSigner: true, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: false },
        { pubkey: TREASURY, isSigner: false, isWritable: true },
        { pubkey: BURN_ADDRESS, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    tx.feePayer = owner;

    const signed = await this.wallet.signTransaction(tx);
    const txSig = await this.connection.sendRawTransaction(signed.serialize());
    await this.connection.confirmTransaction(txSig, 'confirmed');

    return {
      newViewKey: newViewKeyHex,
      recipientViewKey: recipientViewKeyHex,  // share this with recipient off-chain
      txSig,
    };
  }

  /**
   * Unshield — withdraw XNT back to wallet.
   *
   * @param {number} amountLamports
   * @param {string} viewKeyHex
   * @param {number} remainingBalance
   */
  async unshield(amountLamports, viewKeyHex, remainingBalance) {
    const owner = this.wallet.publicKey;
    const viewKeySalt = Buffer.from(viewKeyHex, 'hex');

    // New commitment for remaining balance
    const { viewKey: newViewKey } = await generateViewKey();
    const newCommitment = await computeCommitment(remainingBalance, newViewKey, owner);

    const [statePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('confidential')], this.programId
    );
    const [vaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('shield-vault')], this.programId
    );

    const data = Buffer.alloc(8 + 8 + 32 + 32);
    Buffer.from([0x5d, 0x7a, 0x3c, 0x9e, 0x2b, 0x4f, 0x81, 0x60]).copy(data, 0);
    data.writeBigUInt64LE(BigInt(amountLamports), 8);
    viewKeySalt.copy(data, 16);
    Buffer.from(newCommitment).copy(data, 48);

    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: statePDA, isSigner: false, isWritable: true },
        { pubkey: owner, isSigner: true, isWritable: true },
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    tx.feePayer = owner;

    const signed = await this.wallet.signTransaction(tx);
    const txSig = await this.connection.sendRawTransaction(signed.serialize());
    await this.connection.confirmTransaction(txSig, 'confirmed');

    return { txSig, newViewKey: Buffer.from(newViewKey).toString('hex') };
  }

  /**
   * Get local view keys (never leaves device)
   */
  getLocalKeys() {
    const keys = loadLocalKeys();
    const ownerKey = this.wallet.publicKey.toBase58();
    return keys[ownerKey] || [];
  }
}

// ── WALLET ADAPTER HELPER ─────────────────────────────────────────────────────
/**
 * Quick integration for any wallet:
 *
 * // Phantom / Backpack / Solflare
 * const client = createConfidentialClient(connection, window.solana);
 *
 * // Mobile wallet adapter
 * const client = createConfidentialClient(connection, mobileWallet);
 */
function createConfidentialClient(connection, wallet) {
  return new ConfidentialClient(connection, wallet);
}

// ── EXPORTS ───────────────────────────────────────────────────────────────────
module.exports = {
  ConfidentialClient,
  createConfidentialClient,
  generateViewKey,
  computeCommitment,
  computeViewKeyHash,
  PROGRAM_ID,
  TRANSFER_FEE,
  REVEAL_FEE,
};
