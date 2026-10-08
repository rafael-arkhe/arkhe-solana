use anchor_lang::prelude::*;
use anchor_lang::system_program::System;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod arkhe_verify {
    use super::*;

    pub fn anchor_record(
        _ctx: Context<AnchorRecord>,
        _record_hash: Vec<u8>,
        _metadata_uri: String,
    ) -> Result<()> {
        Ok(())
    }

    pub fn verify_inclusion(
        _ctx: Context<VerifyInclusion>,
        _record_hash: Vec<u8>,
        _proof: Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    pub fn settle_royalty(_ctx: Context<SettleRoyalty>, _amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(record_hash: Vec<u8>)]
pub struct AnchorRecord<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 200, // basic space requirement
        seeds = [b"work", record_hash.as_slice()],
        bump
    )]
    pub work: Account<'info, Work>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(record_hash: Vec<u8>)]
pub struct VerifyInclusion<'info> {
    #[account(
        mut,
        seeds = [b"work", record_hash.as_slice()],
        bump
    )]
    pub work: Account<'info, Work>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SettleRoyalty<'info> {
    #[account(
        mut,
        seeds = [b"work", work.record_hash.as_slice()],
        bump = work.bump
    )]
    pub work: Account<'info, Work>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Recipient of the royalty
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Work {
    pub authority: Pubkey,
    pub record_hash: Vec<u8>,
    pub metadata_uri: String,
    pub bump: u8,
}
