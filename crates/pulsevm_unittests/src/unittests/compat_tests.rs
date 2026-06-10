#[cfg(test)]
mod compat_tests {
    use std::sync::Arc;

    use anyhow::Result;
    use pulsevm_core::{
        authority::PermissionLevel,
        transaction::{Action, Transaction},
        wat2wasm,
    };
    use pulsevm_name_macro::name;

    use crate::tests::{Testing, get_private_key};

    static CONSOLE_WAST: &str = r#"(module
 (import "env" "prints" (func $prints (param i32)))
 (import "env" "prints_l" (func $prints_l (param i32 i32)))
 (import "env" "printi" (func $printi (param i64)))
 (import "env" "printui" (func $printui (param i64)))
 (import "env" "printn" (func $printn (param i64)))
 (import "env" "printhex" (func $printhex (param i32 i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (data (i32.const 0) "hello\00")
 (data (i32.const 16) "world")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $prints (i32.const 0))
  (call $prints_l (i32.const 16) (i32.const 5))
  (call $printi (i64.const -42))
  (call $printui (i64.const 42))
  (call $printn (local.get $0))
  (call $printhex (i32.const 16) (i32.const 2))
 )
)"#;

    static MEM_WAST: &str = r#"(module
 (import "env" "memset" (func $memset (param i32 i32 i32) (result i32)))
 (import "env" "memcpy" (func $memcpy (param i32 i32 i32) (result i32)))
 (import "env" "memcmp" (func $memcmp (param i32 i32 i32) (result i32)))
 (import "env" "eosio_assert" (func $eosio_assert (param i32 i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (data (i32.const 512) "memcmp equal failed\00")
 (data (i32.const 544) "memcmp order failed\00")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (drop (call $memset (i32.const 0) (i32.const 65) (i32.const 16)))
  (drop (call $memcpy (i32.const 32) (i32.const 0) (i32.const 16)))
  (call $eosio_assert
   (i32.eqz (call $memcmp (i32.const 0) (i32.const 32) (i32.const 16)))
   (i32.const 512)
  )
  (drop (call $memset (i32.const 32) (i32.const 66) (i32.const 16)))
  (call $eosio_assert
   (i32.eq (call $memcmp (i32.const 0) (i32.const 32) (i32.const 16)) (i32.const -1))
   (i32.const 544)
  )
 )
)"#;

    static MEMCPY_OVERLAP_WAST: &str = r#"(module
 (import "env" "memcpy" (func $memcpy (param i32 i32 i32) (result i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (drop (call $memcpy (i32.const 4) (i32.const 0) (i32.const 8)))
 )
)"#;

    static ASSERT_FAIL_WAST: &str = r#"(module
 (import "env" "eosio_assert" (func $eosio_assert (param i32 i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (data (i32.const 0) "expected failure\00")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $eosio_assert (i32.const 0) (i32.const 0))
 )
)"#;

    static ASSERT_CODE_FAIL_WAST: &str = r#"(module
 (import "env" "eosio_assert_code" (func $eosio_assert_code (param i32 i64)))
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $eosio_assert_code (i32.const 0) (i64.const 13))
 )
)"#;

    static EXIT_WAST: &str = r#"(module
 (import "env" "eosio_exit" (func $eosio_exit (param i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $eosio_exit (i32.const 0))
  (unreachable)
 )
)"#;

    static BLOCK_NUM_WAST: &str = r#"(module
 (import "env" "get_block_num" (func $get_block_num (result i32)))
 (import "env" "printui" (func $printui (param i64)))
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $printui (i64.extend_i32_u (call $get_block_num)))
 )
)"#;

    static SENDER_WAST: &str = r#"(module
 (import "env" "get_sender" (func $get_sender (result i64)))
 (import "env" "eosio_assert" (func $eosio_assert (param i32 i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (data (i32.const 0) "sender of top-level action should be empty\00")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $eosio_assert (i64.eqz (call $get_sender)) (i32.const 0))
 )
)"#;

    fn push_noop_action(chain: &mut Testing, account: u64) -> Result<pulsevm_core::transaction::TransactionTrace, pulsevm_core::ChainError> {
        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, u32::MAX, 0);
        trx.actions.push(Action {
            account: account.into(),
            name: name!("").into(),
            authorization: vec![PermissionLevel {
                actor: account.into(),
                permission: name!("active").into(),
            }],
            data: Arc::from(vec![]),
        });
        let trx = trx
            .sign(
                &get_private_key(account.into(), "active"),
                chain.controller.chain_id(),
            )
            .unwrap();
        chain.push_transaction(trx)
    }

    #[tokio::test]
    async fn test_console_intrinsics() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("constest").into()], false, true)?;
        chain.set_code(name!("constest").into(), wat2wasm(CONSOLE_WAST)?.into())?;

        let trace = push_noop_action(&mut chain, name!("constest"))?;
        let console = &trace.action_traces[0].console;
        assert_eq!(console, "helloworld-4242constest776f");

        Ok(())
    }

    #[tokio::test]
    async fn test_memcpy_memset_memcmp() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("memtest").into()], false, true)?;
        chain.set_code(name!("memtest").into(), wat2wasm(MEM_WAST)?.into())?;
        push_noop_action(&mut chain, name!("memtest"))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_memcpy_overlap_rejected() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("memtest").into()], false, true)?;
        chain.set_code(name!("memtest").into(), wat2wasm(MEMCPY_OVERLAP_WAST)?.into())?;

        let result = push_noop_action(&mut chain, name!("memtest"));
        let err = match result {
            Ok(_) => panic!("overlapping memcpy should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("memcpy can only accept non-aliasing pointers"),
            "unexpected error: {}",
            err
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_eosio_assert_failure_message() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("asserttest").into()], false, true)?;
        chain.set_code(name!("asserttest").into(), wat2wasm(ASSERT_FAIL_WAST)?.into())?;

        let result = push_noop_action(&mut chain, name!("asserttest"));
        let err = match result {
            Ok(_) => panic!("eosio_assert(0) should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("assertion failure with message: expected failure"),
            "unexpected error: {}",
            err
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_eosio_assert_code_failure() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("asserttest").into()], false, true)?;
        chain.set_code(
            name!("asserttest").into(),
            wat2wasm(ASSERT_CODE_FAIL_WAST)?.into(),
        )?;

        let result = push_noop_action(&mut chain, name!("asserttest"));
        let err = match result {
            Ok(_) => panic!("eosio_assert_code(0, 13) should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("assertion failure with error code: 13"),
            "unexpected error: {}",
            err
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_eosio_exit_terminates_successfully() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("exittest").into()], false, true)?;
        chain.set_code(name!("exittest").into(), wat2wasm(EXIT_WAST)?.into())?;

        // The unreachable after eosio_exit must never execute
        push_noop_action(&mut chain, name!("exittest"))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_num() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("blocktest").into()], false, true)?;
        chain.set_code(name!("blocktest").into(), wat2wasm(BLOCK_NUM_WAST)?.into())?;

        let trace = push_noop_action(&mut chain, name!("blocktest"))?;
        let action_trace = &trace.action_traces[0];
        assert_eq!(action_trace.console, action_trace.block_num.to_string());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_sender_top_level() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("sendertest").into()], false, true)?;
        chain.set_code(name!("sendertest").into(), wat2wasm(SENDER_WAST)?.into())?;

        push_noop_action(&mut chain, name!("sendertest"))?;

        Ok(())
    }
}
