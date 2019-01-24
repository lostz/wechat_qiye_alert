## Usage
create auth file
``` sh
cat  weixin_auth_file.yml
user_id: devops
agent_id: test
corp_id: test
api_secret: test 
db_path: /elastalert/token.db
party_id:
tag_id:
```
create rule file

```
weixin_auth_file: /elastalert/weixin_auth_file.yml
alert:
- "elastalert_modules.wechat_qiye_alert.WeChatAlerter"

```

