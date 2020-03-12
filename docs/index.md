# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect and do various things on a blockchain. 


- hammer -i <account.json> store <filename.txt>
- hammer -i <account.json> share <fileid> <recipientid>
- hammer -i <account.json> open <fileid>
- hammer -i <account.json> select -t [open|share] <fileid> <recipientid>
- hammer -i <account.json> selection <selectionid>
- hammer -i <account.json> exec <selectionid>
- hammer -i <account.json> login [<challenge>]
- hammer -i <account.json> receipt <fileid>
- hammer verify <filename.txt>
- hammer signup -o <account.json>
- hammer new -o <account.json>
- hammer import -o <account.json> -p <recovery phrase>

