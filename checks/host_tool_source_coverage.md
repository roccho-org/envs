# Host Tool v6｜SOURCE証拠と未実証条件の対応

固定版：ADRS [#633 v6](https://github.com/roccho-dev/adrs/pull/633) head `6cac47d5572bfe609f4fc7c893e2701250d7420c`、User #88。**SOURCE証拠の上限**を表にする。Target成功/形式採択はこの表から推論しない。

| 記号 | 公開exact根拠 | 証拠の範囲 |
|---|---|---|
| W | [windows #91](https://github.com/roccho-dev/windows/pull/91) head `355b038bcbe2b24a8ad0121f79b7cc4c72b76b3f` tree `8406cd25827891066eb3d3ec4eeaab4abfabfe07`、[CI 38529430362](https://github.com/roccho-dev/windows/actions/runs/38529430362) 6/6 SUCCESS | Core/Tool分離、生成とOCI試験、geometry-only observer |
| E | [envs #87](https://github.com/roccho-org/envs/pull/87) head `df97ae4f70a1abe3426dda1831b518b0b87a7246` tree `33609f3483d38e129b0cb7f4a8bbe380426a61cd`、[CI 38594653516](https://github.com/roccho-org/envs/actions/runs/38594653516) 8/8 SUCCESS | #86未採択D/q候補を含む合成D/O/authority/stage/rollback SUT；通常入口はfail-closed |
| R | [resources #19](https://github.com/roccho-dev/resources/pull/19) head `5746f46b149c15d57a6ea006f4b79cff60dbf83b` tree `bbdb1db54d59bc89e24cf535632e03e9d6a7ffd9`、[CI 38599405139](https://github.com/roccho-dev/resources/actions/runs/38599405139) source-vm SUCCESS | #17 current Producer pinとNative/OCI VMを保持、Host relationの隔離SOURCEテストも同jobでSUCCESS |
| P | [envs #89](https://github.com/roccho-org/envs/pull/89) のv5公開SOURCE照合と、本表のX（envs #92・凍結済みv6検証器） | v5は#91/#87/#19、XはF1 #90/F2 #93/R #19をそれぞれ実GitHub GETで検証。**両者とも本番S4ではない** |
| ADRS | [設計v6](https://github.com/roccho-dev/adrs/pull/633)および親[v4](https://github.com/roccho-dev/adrs/blob/b6d837157454764c4b5c9fd83d66b177e7b4a53b/decisions/host-native-oci-update-integration-261014.jsonl)、[v5](https://github.com/roccho-dev/adrs/blob/a38d5330503c55bbdd7f5a571ed1f889f46595f2/decisions/host-native-oci-update-integration-261014.jsonl) | 設計合意。製品のGO・LIVE権限ではない |

**凡例：** `SOURCE`=独立Rが限定受容したsource/VM、`SYNTHETIC`=入力が合成/模擬、`UNPROVEN`=本番/実Target確認がない。すべての行で正式`D_ADMITTED=false`、`TARGET_READY=false`、`S4_REAL_COMPOSITE_GREEN=false`。利用する固定checkのSUCCESSは実HeadのSOURCE上のもの。個々の行の結果を実Host成功へ昇格しない。

## v6 現行F1・F2・横断SOURCEの独立R受容済み固定版

以下は**旧head上で独立Rが技術受容したSOURCE証拠**であり、このファイルを編集した新headの自己証明でも、正式D／Relationの採択でもない。表中の`SOURCE-proven:F1/F2/X/R`は該当する公開CI実行・材料結合の証拠参照であり、各V/S/L条件が実Targetで成立したという意味ではない。

| 証拠ID | 固定SOURCE head / tree | exact CI・固定R | 技術的に証明した上限 |
|---|---|---|---|
| F1 | [envs #90](https://github.com/roccho-org/envs/pull/90) `dda51699ff6b6892f11b8f1a46153047e5ffb74f` / `810501fafe4771d94440718c5cc0ef6c2371b999` | [CI 38634669573](https://github.com/roccho-org/envs/actions/runs/38634669573) 8/8 SUCCESS / [R 5524498474](https://github.com/roccho-org/envs/pull/90#pullrequestreview-5524498474) | 未採択Relation ↔ Host/Target/Unit ↔ proposed q の**合成**functional bindingと偽bindingの拒否。真正D/admissionではない |
| F2 | [windows #93](https://github.com/roccho-dev/windows/pull/93) `4fc9548d81d6a724ffbf1e8a24c5936e48a70f10` / `10fb840d4c412670ab78a94da672d02e3937e057` | [CI 38637482002](https://github.com/roccho-dev/windows/actions/runs/38637482002) **attempt 2** 6/6 SUCCESS / [R 5525335505](https://github.com/roccho-dev/windows/pull/93#pullrequestreview-5525335505) | 同一F1 blob/qを用いた**使い捨て本物Nix/OCI** Tool選択・読取・拒否試験。attempt 1のdev 403失敗は履歴保持。実PC7337/WSLCではない |
| X | [envs #92](https://github.com/roccho-org/envs/pull/92) **凍結済みのR受容head** `b82713b02c06fe65082f557fce9bcf710c6e723f` / `a04756a35341f794620ccbc48140044610e7b73e` | [CI 38646956225](https://github.com/roccho-org/envs/actions/runs/38646956225) 8/8 SUCCESS / [R 5525631594](https://github.com/roccho-org/envs/pull/92#pullrequestreview-5525631594) | F1/F2/Rの凍結SOURCE・attempt・q/blobとProducer pinを**公開GitHub GET**で突合。新headによる追加修正は別途CI/Rが必要 |
| R | [resources #19](https://github.com/roccho-dev/resources/pull/19) `5746f46b149c15d57a6ea006f4b79cff60dbf83b` / `bbdb1db54d59bc89e24cf535632e03e9d6a7ffd9` | [CI 38599405139](https://github.com/roccho-dev/resources/actions/runs/38599405139) source-vm SUCCESS / [R 5521439539](https://github.com/roccho-dev/resources/pull/19#pullrequestreview-5521439539) | contains/manages/任意wrapの隔離fixtureとNative/OCI VM、正式Relation schema/実Host権限は未採択 |

**各行の区分:** `SYNTHETIC` = 合成SUTや純粋判定試験、`SOURCE-proven:ID` = R受容済みheadの実SOURCE/CIから関連する部分だけ確認可能、`REAL_TARGET_UNPROVEN` = 実Hostのadmission・READ/CHANGE/quiet/O/effect/receiptは未証明。**SOURCE-proven は行全体の本番保証ではない。** F1/F2/Xの同一blob `cee080d45e3e7dea8d3c0a608dd2827659101d45` と proposed q `sha256:f531f4c49182a8cf15475103c1890475cefbb634512baf3d3b2fd9369da445a4` の連結はXのSOURCE証拠に限る。

## V01–V14｜Target更新判定（14）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 | v6の証拠区分 |
|---|---|---|---|---|
| V01 | 承認T1/実T0の更新候補 | E:合成D/O比較 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v01_v03_desired_tool_diff_even_when_source_unchanged` | 合成のみ。実D/Oと変更許可未証明 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V02 | 対象ごとに別Dを採用可能 | E:target_ref別q · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v02_separate_target_chooses_old_tool_not_newest_producer` | 採択済Dは未存在 | SYNTHETIC ; SOURCE-proven:F1 ; REAL_TARGET_UNPROVEN |
| V03 | source不変でもTarget未達ならNOOP不可 | E:合成O≠D; W/R:別世代 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v01_v03_desired_tool_diff_even_when_source_unchanged` | 実Target Oなし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V04 | 切替結果UNKNOWNは盲再送しない | E:previous=UNKNOWN拒否 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v04_v05_unknown_old_effect_blocks_even_when_versions_look_matching` | 実作用の復旧未検証 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V05 | 見かけT1でも未知作用は成功でない | E:E_UNKNOWN · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v04_v05_unknown_old_effect_blocks_even_when_versions_look_matching` | 実O/receiptなし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V06 | 新T成立・結果保存未了なら再切替不要 | E:readback候補 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v06_v07_matching_current_d_and_o_still_need_real_receipt` | 実記録/receiptなし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V07 | D/O/結果一致後だけ成功 | E:合成readbackのみ · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v06_v07_matching_current_d_and_o_still_need_real_receipt` | 正式D・効果証拠は未採択 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V08 | 実Bが違えばTool-onlyにしない | W/R:BとT独立VM · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v08_different_base_demands_separate_plan` | 実B観測なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V09 | D形式未採択なら変更しない | E:NOT_ADMITTED, effect=FORBIDDEN · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v09_unadmitted_d_must_stop_noop_and_change` | 正式ownerのadmission待ち | SYNTHETIC ; SOURCE-proven:F1 ; REAL_TARGET_UNPROVEN |
| V10 | 切替中Dq置換は旧q成功でない | E:revision mismatch · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v10_old_revision_cannot_be_used_as_current_success` | 実採用変更中断未試験 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V11 | 古い・欠落OをSuccessにしない | E:fresh=false拒否 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v11_observation_missing_stale_or_invalid` | 実Target read未許可 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V12 | quiet後に他writerが入れば拒否 | E:quiet/single_writerの合成拒否 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v12_concurrent_writer_or_lost_quiet_denies_real_change` | 連続agent子孫の静止/排他未実証 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V13 | 版一致だけでsession・機能成功にしない | W/R:CIのCLIと模擬状態 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v13_closure_or_auth_session_checks_missing_denies` | 実auth/session・作業継続未確認 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| V14 | 起動・Binding差があれば別計画 | W/R:OCI image/VM起動試験 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v14_binding_launch_or_state_change_is_not_tool_only` | 実Target Bindingとconfig未確認 | SYNTHETIC ; SOURCE-proven:F1 ; REAL_TARGET_UNPROVEN |

## S1–A3｜Host/Build/Generation/配置/受入（22）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 | v6の証拠区分 |
|---|---|---|---|---|
| S1 | Host IDをrepo/OSから生成しない | E:target_ref明示 · `SOURCE-SUT:checks/test_host_tool_normal_entry.py#test_unadmitted_proposal_is_not_an_accepted_contract_or_effect` | 実Host relation投入未実証 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| S2 | 不正contains関係を拒否 | resources #19 `nixos/tests/host_relation_source.py#test_containment_cycles_self_and_multi_parent_refused_same_scope` が自己・循環・同scope多親を拒否。実 `source-vm` step `Test synthetic Host contains/manages/optional wrap (NOT_ADMITTED)` SUCCESSを横断gateで必須化：`SOURCE-RELATION:roccho-dev/resources#19/nixos/tests/host_relation_source.py#test_containment_cycles_self_and_multi_parent_refused_same_scope` | **合成関係テストのみ**。正式Host relation意味/入力schema/実稼働instanceはADRS/resources owner未採択 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| S3 | Native/OCIと別storeを区別 | R:Native-only VMとOCI VM · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_same_target_tool_delta_does_not_mutate_base_or_work` | 実Host/別store受入は未試験 | SYNTHETIC ; SOURCE-proven:F2 ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| S4 | Producer C/envs D/Target O/Eを分離 | F1 #90:提案D/q、F2 #93:隔離実Nix/O、X #92:凍結SOURCE横断照合（非循環）、R #19:Relation VM。**各責務はSOURCE上で独立** | 採択D／実Target O/E／本番一本S4は未実証 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; SOURCE-proven:X ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| B1 | 固定Tool pin、latest禁止 | W:fixed flake; R:lock · `SOURCE-SUT:checks/test_host_tool_normal_entry.py#test_forged_tool_admission_into_ordinary_bindings_is_rejected` | 正式D採用は未実施 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| B2 | B/T独立とproducer前後差 | W:own/rent B-only; R:VM · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v08_different_base_demands_separate_plan` | 実HostでTool-only更新未実施 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| B3 | Source差分とD/O差を分ける | E:proposed_qと合成judge · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v01_v03_desired_tool_diff_even_when_source_unchanged` | D/Oの実観測なし | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| B4 | CLI/Pi/role Tool条件 | W:pin付きown/rent SOURCE · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_same_target_tool_delta_does_not_mutate_base_or_work` | 対象ごとの実ツール更新未試験 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| B5 | 欠落closure/取得失敗拒否 | W:negative OCI; R:VM closure import · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_state_unknown_or_foreign_selector_stops_even_synthetic_change` | 実輸送・実GC未実証 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G1 | 初回Base-onlyにToolなし | W/R:empty Tool CI · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_first_base_only_requires_explicit_d_and_change_guard` | 実Host初回採用なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G2 | Tool世代とGC保護 | W:Nix-native/GC OCI fixture · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_rollback_only_same_attempt_and_same_preimage` | 実Target GC未実施 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G3 | 再起動/再作成と選択維持 | W/R:OCI restart/recreate · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_same_target_tool_delta_does_not_mutate_base_or_work` | 実Host session完全性未実証 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G4 | 変更中の静止を継続保持 | W:CI synthetic quiet; E:boolean guard · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_target_change_requires_every_stage_local_condition_and_resolved_effect` | 実Agent/子孫排他未証明 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G5 | foreign/所有権/破損拒否 | W:read-selected/profile negatives · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_state_unknown_or_foreign_selector_stops_even_synthetic_change` | 実旧volume観測なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| G6 | 失敗とUNKNOWNを分けて復旧 | E:synthetic E_UNKNOWN/read · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_unknown_after_actual_selector_write_does_not_blind_retry` | 実effectのreadback不可 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| H1 | own Host別版 | W:own test; R:own OCI · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v02_separate_target_chooses_old_tool_not_newest_producer` | 実own Target未適用 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| H2 | rent Host別版 | W:rent-native/OCI CI · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_same_target_tool_delta_does_not_mutate_base_or_work` | 実rent Target未適用 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| H3 | NixOS OCI版 | R:OCI VM · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v08_different_base_demands_separate_plan` | 実NixOS Host未適用 | SYNTHETIC ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| H4 | NixOS Native版 | R:Native-only VM · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v08_different_base_demands_separate_plan` | 実Native Host未適用 | SYNTHETIC ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| A1 | 同じ版を独立Rが評価 | F1 #90 [R 5524498474](https://github.com/roccho-org/envs/pull/90#pullrequestreview-5524498474)、F2 #93 [R 5525335505](https://github.com/roccho-dev/windows/pull/93#pullrequestreview-5525335505)、X #92 [R 5525631594](https://github.com/roccho-org/envs/pull/92#pullrequestreview-5525631594)、R #19 [R 5521439539](https://github.com/roccho-dev/resources/pull/19#pullrequestreview-5521439539) | 局所R受容であり全SOURCE／本番S4の一括承認ではない | SOURCE-proven:F1 ; SOURCE-proven:F2 ; SOURCE-proven:X ; SOURCE-proven:R ; REAL_TARGET_UNPROVEN |
| A2 | 候補/D/O/E/admission区別 | E:NOT_ADMITTED guard · `SOURCE-SUT:checks/test_host_tool_normal_entry.py#test_forged_tool_admission_into_ordinary_bindings_is_rejected` | 実D/O/Eの連結なし | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; SOURCE-proven:X ; REAL_TARGET_UNPROVEN |
| A3 | 第二正本/engine/daemonを追加しない | W/E/R差分限定 · `SOURCE-SUT:checks/test_host_tool_normal_entry.py#test_existing_provider_and_projection_do_not_import_fixture_candidate` | 本番更新入口未完成 | SYNTHETIC ; SOURCE-proven:X ; REAL_TARGET_UNPROVEN |

## L01–L28｜中断・継続・読取と変更の分離（28）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 | v6の証拠区分 |
|---|---|---|---|---|
| L01 | envs形式不足の担当・再開 | E:未採択proposalとR記録 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_read_does_not_require_dev_go_d_o_or_effect_resolution` | 正式D owner判断/開始未確認 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L02 | 許可内SOURCE是正をP待ちにしない | W/R/E複数SOURCE反復 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_source_fix_can_continue_with_unrelated_target_unknown` | 実TargetのGOとは別 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L03 | 別repo/新作用は境界確認 | R:独立resources候補PR · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_forged_scope_and_shape_refused` | LIVE変更許可なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L04 | P受理だけで完了にしない | PR review/証拠分離 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_external_wait_or_safe_decline_must_be_recorded` | 実P受理→実開始未観測 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L05 | P却下や外部待ちの扱い | ADRS v5設計のみ · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_external_wait_or_safe_decline_must_be_recorded` | 現P応答/復帰条件未実装 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L06 | API受付と担当実開始を分離 | ADRS v5設計のみ · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_handoff_requires_assigned_actual_start_not_ack` | 実provider開始証拠なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L07 | 応答喪失後は照合だけ | E:E_UNKNOWN/read分離 · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_unknown_after_actual_selector_write_does_not_blind_retry` | 実作用追跡なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L08 | executor停止を稼働と誤認しない | ADRS v5設計のみ · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_observed_start_can_be_real_but_unauthorized` | 実停止・復帰証拠なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L09 | W消失の暗黙交代禁止 | 固定W/R identity記録 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_forged_scope_and_shape_refused` | 実交代・排他未試験 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L10 | R消失時のW自己承認禁止 | 固定Rの別review · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_handoff_requires_assigned_actual_start_not_ack` | 独立R不在時試験なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L11 | 二重発火/重複writer拒否 | E:single_writer=false拒否 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_target_change_requires_every_stage_local_condition_and_resolved_effect` | 実発火排他/attempt未試験 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L12 | source/head変更で再review | #86/#15/#17 exact CIとR · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_source_fix_can_continue_with_unrelated_target_unknown` | 過去headの証拠は流用せず | SYNTHETIC ; SOURCE-proven:X ; REAL_TARGET_UNPROVEN |
| L13 | 旧Dqで新Dを変更しない | E:q/target mismatch拒否 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v10_old_revision_cannot_be_used_as_current_success` | 正式Dの版替え未実証 | SYNTHETIC ; SOURCE-proven:F1 ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L14 | SOURCEはGreenでもTarget旧版あり得る | E:target_noop=UNPROVEN · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v01_v03_desired_tool_diff_even_when_source_unchanged` | 実Target Oなし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L15 | 残作用のみ再開 | E:unknown/read guard · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_unknown_after_actual_selector_write_does_not_blind_retry` | 実残作用/実開始の記録なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L16 | T成立・結果保存不足だけ処理 | E:SYNTHETIC_READBACK_CANDIDATE · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_unknown_after_actual_selector_write_does_not_blind_retry` | 実receipt保存なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L17 | R設計合意とGOを分ける | PR Draft/未merge/効果なし · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_observed_start_can_be_real_but_unauthorized` | 正式admissionなし | SYNTHETIC ; SOURCE-proven:X ; REAL_TARGET_UNPROVEN |
| L18 | source不変≠NOOP | E:synthetic compare · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v01_v03_desired_tool_diff_even_when_source_unchanged` | 実OとDの照合なし | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L19 | 開発GOなしで許可済readを行える | E:read independently allowed · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_read_does_not_require_dev_go_d_o_or_effect_resolution` | 実Host read許可なし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L20 | 開発GOあってもread権限なければ拒否 | E:READ_AUTH_REQUIRED · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_read_must_have_actual_target_actor_scope_route_safety_no_duplicate` | 実read permission別承認未 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L21 | 断片的OではUNKNOWNを解消しない | E:O_UNKNOWN_OR_STALE · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v11_observation_missing_stale_or_invalid` | 実Target断片の照合未試験 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L22 | UNKNOWNで新T成立→記録だけ残る | E:synthetic matching receipt · `SOURCE-SUT:checks/test_host_tool_transition_sut.py#test_unknown_after_actual_selector_write_does_not_blind_retry` | 実記録不足/旧作用未検証 | SYNTHETIC ; SOURCE-proven:F2 ; REAL_TARGET_UNPROVEN |
| L23 | UNKNOWN解消後もchange許可を別確認 | E:synthetic CHANGE preconditions · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_target_change_requires_every_stage_local_condition_and_resolved_effect` | 実change許可/quiet未実証 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L24 | 無許可開始の観測≠許可済開始 | ADRS v6設計のみ · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_observed_start_can_be_real_but_unauthorized` | 実ObservedStarted追跡未実装 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L25 | 旧qの読取は可能・旧q変更禁止 | E:q mismatch/READ分離 · `SOURCE-SUT:checks/test_host_tool_target_gap.py#test_v10_old_revision_cannot_be_used_as_current_success` | 実旧q readback未実施 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L26 | 経路停止/actor不一致/重複を拒否 | E:foreign target/authority拒否 · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_forged_scope_and_shape_refused` | 実provider経路の復旧未検証 | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L27 | サービス起動はreadでなくeffect | ADRS v6設計のみ · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_recovery_restart_is_mutation_and_not_read` | 実復旧許可/receiptなし | SYNTHETIC ; REAL_TARGET_UNPROVEN |
| L28 | Target UNKNOWNでも独立SOURCE是正可 | W/E/R SOURCE CI/独立R · `SOURCE-SUT:checks/test_host_tool_continuation.py#test_source_fix_can_continue_with_unrelated_target_unknown` | Target UNKNOWNの実影響は未検証 | SYNTHETIC ; REAL_TARGET_UNPROVEN |

## 未完了として必ず残す条件

- **正式Dと実Target**：P/envs ownerのadmission、適用対象とactorの現在identity、読取許可と別の変更許可、fresh O/closure、実agentと子孫の連続静止・単一writer、UNKNOWNの限定照合、残作用と効果receipt、状態/認証/session/repo/volume保持、rollback/GC/readback。
- **SOURCE横断**：このPRが実Githubの候補を取得・検証することと、#88が求める全要求の実行済み最終S4合成/受入は別。新しいPR headのCI実行中に、そのrun自身の完成を事前に要求しない。W/E/Rは固定旧候補であり、#87に追加された新codeのSOURCE結果は別版CI/Rで判定する。
- **作用境界**：この表とfixtureは読み取り専用。レビュー済みSOURCEをmerge/deployする許可も、実Hostを読む/書く許可も生成しない。既存W/R固定、追加actor/route/secretなし。


## v5 executable SOURCE-SUT references

`SOURCE-SUT:checks/*.py#test_*` は、この表の既存証拠を置換するものではなく、**実行する合成反例の補助参照**。元の各行の実Target未証明条件は消さない。CIは該当test fileとmethod存在・実unit test SUCCESSを確認し、ID一覧だけでSOURCE受入と呼ばない。

- `host_tool_continuation.evaluate()` はReadReady（D未採択/旧E UNKNOWNでも読取条件を別判定）、工程別ChangeReady、ObservedStartedとAuthorizedStarted/BoundaryHandledを分離する純粋な非実行fixture。
- `target_gap()` は `I=(target,unit,B,T,launch,config_binding,state_contract)` を合成D/Oの実値で比較。差`{T}`だけと、Base/launch/binding/state差、q古さ、未解決作用、観測欠落を区別し、**常にNOOP/SuccessをUNPROVEN**とする。
- `test_host_tool_transition_sut.py` は使い捨てTempDirectoryのTool世代symlinkを実際に切替え、途中停止/UNKNOWN/重複送信/rollback/状態保持を検証する。real `nix-env`操作・OCI/Native起動は別のwindows/resources既存SOURCE CIにのみ証拠があり、このPython SUTが実Host Nixを実行したとはしない。
- `test_host_tool_normal_entry.py` は通常のenvs既存`contract_projection.project()`を実呼び出しし、未採択Host Tool D/偽admissionを拒否する。現prod Provider/Host entryへ新D入力を密かに追加しない。
- `S2`の`contains/manages/wrap`は[resources #19](https://github.com/roccho-dev/resources/pull/19) exact head・[CI 38599405139](https://github.com/roccho-dev/resources/actions/runs/38599405139)の隔離fixture/Native VMで確認。旧#18のBrowser-SUID VM REDは別baseの履歴として残す。**ADRS #630/resources #1の正式relation意味・正本schemaは未採択**。Local Target ID反例をrelationの直接証拠に流用しない。

**必要な残owner判断**：正式Dのターゲット/ユニット/版/B/T/launch/config/state含意とqの採択・読取/変更権限、relationの意味/Host IDの正規source、実Targetの連続quietとagent子孫/単一writerの実施入口、事故後の既存provider receipt/recoveryの配置。合成TRUEやID対応だけではSOURCEからLIVEへ進めず、固定Rのexact版独立判断を待つ。


## v5 latest triple S2 external SOURCE evidence

- 以前のS2行が参照していた`test_target_unit_not_derived_from_repo_or_oci_path`は**Host relationのcontainsを検査せず偽陽性**だったため、S2のSOURCE根拠から退役。変更前のテスト自体はTarget/Unit識別の独立試験として残す。
- resources [#19](https://github.com/roccho-dev/resources/pull/19)の凍結head/tree、`nixos/tests/host_relation_source.py`のGit blob `4aa50be2c62c714def0b2aa97aa24573bd8b5344`、指定test method、およびrun 38599405139の実 `source-vm` jobの`Test synthetic Host contains/manages/optional wrap (NOT_ADMITTED)` **SUCCESS**を、後続検証器が公開GitHub GETで照合。S2の試験が欠落/失敗/SKIPPEDなら検証器はPASSにしない。
- 上記の事実はSOURCEと合成relationのみに有効。旧resources #18のBrowser SUID sandbox FATAL/VM RED、ADRS #630/resources #1の正式Host relation採択、実Host同時性や管理権限/稼働/作用の証拠には昇格しない。
- 最新 SOURCE `windows #91 / envs #87 / resources #19`はすべて独立Rで限定技術GREENの**前段候補**。この後続検証器のrunが自分自身を検証対象に含めて循環しないよう、まだ未完了の新CI headはsnapshotに入れない。`D_ADMITTED=false`、`TARGET_READY=false`、`S4_REAL_COMPOSITE_GREEN=false`、`MERGE_READY=false`を維持。
