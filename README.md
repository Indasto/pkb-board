# pkb-board

[Indasto/pkb](https://github.com/Indasto/pkb)（private）のタスクを表示・操作する Web ボードの画面だけを置いたリポジトリです。
タスクのデータはここには無く、ブラウザから GitHub API で private リポジトリを読み書きします（アクセストークンは各ブラウザ内にのみ保存）。

ソースは pkb リポジトリの `web/index.html`。更新は pkb 側で `node scripts/publish-web.mjs` を実行します。
