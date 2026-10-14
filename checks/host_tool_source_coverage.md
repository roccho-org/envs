# Host Tool v6｜SOURCE証拠と未実証条件の対応

固定版：ADRS [#633 v6](https://github.com/roccho-dev/adrs/pull/633) head `6cac47d5572bfe609f4fc7c893e2701250d7420c`、User #88。**SOURCE証拠の上限**を表にする。Target成功/形式採択はこの表から推論しない。

| 記号 | 公開exact根拠 | 証拠の範囲 |
|---|---|---|
| W | [windows #91](https://github.com/roccho-dev/windows/pull/91) head `355b038bcbe2b24a8ad0121f79b7cc4c72b76b3f` tree `8406cd25827891066eb3d3ec4eeaab4abfabfe07`、[CI 38529430362](https://github.com/roccho-dev/windows/actions/runs/38529430362) 6/6 SUCCESS | Core/Tool分離、生成とOCI試験、geometry-only observer |
| E | [envs #86](https://github.com/roccho-org/envs/pull/86) head `b3afeb156c2fca9eb93256c9b66b0a8b96bd1068` tree `a0a94e6ff490126279a5fa7cafa5ae30328cf110`、[CI 38551552641](https://github.com/roccho-org/envs/actions/runs/38551552641) 8/8 SUCCESS | 未採択D/q候補、合成D/O/authority guard、申告値合成 |
| R | [resources #17](https://github.com/roccho-dev/resources/pull/17) head `d5cfc205ef718473a615b2606b61eb35402c9d59` tree `2f61a46ea05ba990486790bcbdb9b6af6811b758`、[CI 38560548295](https://github.com/roccho-dev/resources/actions/runs/38560548295) 1/1 SUCCESS | 旧#15と別SOURCE、現Producer pinでB-only OCI/Native別世代VM |
| P | このPR #87の `checks/host_tool_source_provenance.py` と既存CI | 公開GitHub PR/commit/run/job/source pinの実照合 **候補のみ**（独立R未評価） |
| ADRS | [設計v6](https://github.com/roccho-dev/adrs/pull/633)および親[v4](https://github.com/roccho-dev/adrs/blob/b6d837157454764c4b5c9fd83d66b177e7b4a53b/decisions/host-native-oci-update-integration-261014.jsonl)、[v5](https://github.com/roccho-dev/adrs/blob/a38d5330503c55bbdd7f5a571ed1f889f46595f2/decisions/host-native-oci-update-integration-261014.jsonl) | 設計合意。製品のGO・LIVE権限ではない |

**凡例：** `SOURCE`=独立Rが限定受容したsource/VM、`SYNTHETIC`=入力が合成/模擬、`UNPROVEN`=本番/実Target確認がない。すべての行で正式`D_ADMITTED=false`、`TARGET_READY=false`、`S4_REAL_COMPOSITE_GREEN=false`。利用する固定checkのSUCCESSは実HeadのSOURCE上のもの。個々の行の結果を実Host成功へ昇格しない。

## V01–V14｜Target更新判定（14）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 |
|---|---|---|---|
| V01 | 承認T1/実T0の更新候補 | E:合成D/O比較 | 合成のみ。実D/Oと変更許可未証明 |
| V02 | 対象ごとに別Dを採用可能 | E:target_ref別q | 採択済Dは未存在 |
| V03 | source不変でもTarget未達ならNOOP不可 | E:合成O≠D; W/R:別世代 | 実Target Oなし |
| V04 | 切替結果UNKNOWNは盲再送しない | E:previous=UNKNOWN拒否 | 実作用の復旧未検証 |
| V05 | 見かけT1でも未知作用は成功でない | E:E_UNKNOWN | 実O/receiptなし |
| V06 | 新T成立・結果保存未了なら再切替不要 | E:readback候補 | 実記録/receiptなし |
| V07 | D/O/結果一致後だけ成功 | E:合成readbackのみ | 正式D・効果証拠は未採択 |
| V08 | 実Bが違えばTool-onlyにしない | W/R:BとT独立VM | 実B観測なし |
| V09 | D形式未採択なら変更しない | E:NOT_ADMITTED, effect=FORBIDDEN | 正式ownerのadmission待ち |
| V10 | 切替中Dq置換は旧q成功でない | E:revision mismatch | 実採用変更中断未試験 |
| V11 | 古い・欠落OをSuccessにしない | E:fresh=false拒否 | 実Target read未許可 |
| V12 | quiet後に他writerが入れば拒否 | E:quiet/single_writerの合成拒否 | 連続agent子孫の静止/排他未実証 |
| V13 | 版一致だけでsession・機能成功にしない | W/R:CIのCLIと模擬状態 | 実auth/session・作業継続未確認 |
| V14 | 起動・Binding差があれば別計画 | W/R:OCI image/VM起動試験 | 実Target Bindingとconfig未確認 |

## S1–A3｜Host/Build/Generation/配置/受入（22）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 |
|---|---|---|---|
| S1 | Host IDをrepo/OSから生成しない | E:target_ref明示 | 実Host relation投入未実証 |
| S2 | 不正contains関係を拒否 | ADRS #633 v6設計 | 実relation source fixture未確認 |
| S3 | Native/OCIと別storeを区別 | R:Native-only VMとOCI VM | 実Host/別store受入は未試験 |
| S4 | Producer C/envs D/Target O/Eを分離 | W/E/R SOURCE別責務 | 現Targetへの正規接続は未実装 |
| B1 | 固定Tool pin、latest禁止 | W:fixed flake; R:lock | 正式D採用は未実施 |
| B2 | B/T独立とproducer前後差 | W:own/rent B-only; R:VM | 実HostでTool-only更新未実施 |
| B3 | Source差分とD/O差を分ける | E:proposed_qと合成judge | D/Oの実観測なし |
| B4 | CLI/Pi/role Tool条件 | W:pin付きown/rent SOURCE | 対象ごとの実ツール更新未試験 |
| B5 | 欠落closure/取得失敗拒否 | W:negative OCI; R:VM closure import | 実輸送・実GC未実証 |
| G1 | 初回Base-onlyにToolなし | W/R:empty Tool CI | 実Host初回採用なし |
| G2 | Tool世代とGC保護 | W:Nix-native/GC OCI fixture | 実Target GC未実施 |
| G3 | 再起動/再作成と選択維持 | W/R:OCI restart/recreate | 実Host session完全性未実証 |
| G4 | 変更中の静止を継続保持 | W:CI synthetic quiet; E:boolean guard | 実Agent/子孫排他未証明 |
| G5 | foreign/所有権/破損拒否 | W:read-selected/profile negatives | 実旧volume観測なし |
| G6 | 失敗とUNKNOWNを分けて復旧 | E:synthetic E_UNKNOWN/read | 実effectのreadback不可 |
| H1 | own Host別版 | W:own test; R:own OCI | 実own Target未適用 |
| H2 | rent Host別版 | W:rent-native/OCI CI | 実rent Target未適用 |
| H3 | NixOS OCI版 | R:OCI VM | 実NixOS Host未適用 |
| H4 | NixOS Native版 | R:Native-only VM | 実Native Host未適用 |
| A1 | 同じ版を独立Rが評価 | PR #91/#86/#17独立R | S4全体の独立受入なし |
| A2 | 候補/D/O/E/admission区別 | E:NOT_ADMITTED guard | 実D/O/Eの連結なし |
| A3 | 第二正本/engine/daemonを追加しない | W/E/R差分限定 | 本番更新入口未完成 |

## L01–L28｜中断・継続・読取と変更の分離（28）

| ID | 期待する事実・拒否 | 既存証拠の所在 | 未達の厳密な境界 |
|---|---|---|---|
| L01 | envs形式不足の担当・再開 | E:未採択proposalとR記録 | 正式D owner判断/開始未確認 |
| L02 | 許可内SOURCE是正をP待ちにしない | W/R/E複数SOURCE反復 | 実TargetのGOとは別 |
| L03 | 別repo/新作用は境界確認 | R:独立resources候補PR | LIVE変更許可なし |
| L04 | P受理だけで完了にしない | PR review/証拠分離 | 実P受理→実開始未観測 |
| L05 | P却下や外部待ちの扱い | ADRS v5設計のみ | 現P応答/復帰条件未実装 |
| L06 | API受付と担当実開始を分離 | ADRS v5設計のみ | 実provider開始証拠なし |
| L07 | 応答喪失後は照合だけ | E:E_UNKNOWN/read分離 | 実作用追跡なし |
| L08 | executor停止を稼働と誤認しない | ADRS v5設計のみ | 実停止・復帰証拠なし |
| L09 | W消失の暗黙交代禁止 | 固定W/R identity記録 | 実交代・排他未試験 |
| L10 | R消失時のW自己承認禁止 | 固定Rの別review | 独立R不在時試験なし |
| L11 | 二重発火/重複writer拒否 | E:single_writer=false拒否 | 実発火排他/attempt未試験 |
| L12 | source/head変更で再review | #86/#15/#17 exact CIとR | 過去headの証拠は流用せず |
| L13 | 旧Dqで新Dを変更しない | E:q/target mismatch拒否 | 正式Dの版替え未実証 |
| L14 | SOURCEはGreenでもTarget旧版あり得る | E:target_noop=UNPROVEN | 実Target Oなし |
| L15 | 残作用のみ再開 | E:unknown/read guard | 実残作用/実開始の記録なし |
| L16 | T成立・結果保存不足だけ処理 | E:SYNTHETIC_READBACK_CANDIDATE | 実receipt保存なし |
| L17 | R設計合意とGOを分ける | PR Draft/未merge/効果なし | 正式admissionなし |
| L18 | source不変≠NOOP | E:synthetic compare | 実OとDの照合なし |
| L19 | 開発GOなしで許可済readを行える | E:read independently allowed | 実Host read許可なし |
| L20 | 開発GOあってもread権限なければ拒否 | E:READ_AUTH_REQUIRED | 実read permission別承認未 |
| L21 | 断片的OではUNKNOWNを解消しない | E:O_UNKNOWN_OR_STALE | 実Target断片の照合未試験 |
| L22 | UNKNOWNで新T成立→記録だけ残る | E:synthetic matching receipt | 実記録不足/旧作用未検証 |
| L23 | UNKNOWN解消後もchange許可を別確認 | E:synthetic CHANGE preconditions | 実change許可/quiet未実証 |
| L24 | 無許可開始の観測≠許可済開始 | ADRS v6設計のみ | 実ObservedStarted追跡未実装 |
| L25 | 旧qの読取は可能・旧q変更禁止 | E:q mismatch/READ分離 | 実旧q readback未実施 |
| L26 | 経路停止/actor不一致/重複を拒否 | E:foreign target/authority拒否 | 実provider経路の復旧未検証 |
| L27 | サービス起動はreadでなくeffect | ADRS v6設計のみ | 実復旧許可/receiptなし |
| L28 | Target UNKNOWNでも独立SOURCE是正可 | W/E/R SOURCE CI/独立R | Target UNKNOWNの実影響は未検証 |

## 未完了として必ず残す条件

- **正式Dと実Target**：P/envs ownerのadmission、適用対象とactorの現在identity、読取許可と別の変更許可、fresh O/closure、実agentと子孫の連続静止・単一writer、UNKNOWNの限定照合、残作用と効果receipt、状態/認証/session/repo/volume保持、rollback/GC/readback。
- **SOURCE横断**：このPRが実Githubの候補を取得・検証することと、#88が求める全要求の実行済み最終S4合成/受入は別。新しいPR headのCI実行中に、そのrun自身の完成を事前に要求しない。W/E/Rは固定旧候補であり、#87に追加された新codeのSOURCE結果は別版CI/Rで判定する。
- **作用境界**：この表とfixtureは読み取り専用。レビュー済みSOURCEをmerge/deployする許可も、実Hostを読む/書く許可も生成しない。既存W/R固定、追加actor/route/secretなし。

