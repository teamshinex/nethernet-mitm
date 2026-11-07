# nethernet-mitm
MCBE 멀티플레이어 플랫폼 구축을 지원하기 위한 LAN, BDS에 지원되는 nethernet mitm 프록시입니다.

**자기 것인 것처럼 이것을 무단 배포하는 경우, 구조를 뜯고 베껴 사용하는 경우는 제 (waternoob1005) 허락 없이 절대 불가능합니다.**
## 사용법
`relay --port 24523 --token 내토큰`

`host --relay <중계서버 주소>:24523 --id myworld --token 내토큰 --upstream-lan broadcast`

`join --relay <중계서버 주소>:24523 --id myworld`

위처럼 사용이 가능하며, `<중계서버 주소>` 에는 relay를 실행하는 측의 공인 IP를 두어야 합니다.
`24523`은 relay 측에서 포워딩 해야 할 포트입니다.

host와 relay에 있는 내토큰 은 동일해야 합니다.

host에 `--upstream-lan broadcast` 가 있을 경우에는 LAN 서버 경유,
`--upstream-http http://127.0.0.1:19132` 가 있을 경우에는 19132로 열린 BDS를 경유합니다.

제 컴퓨터에서는 똑바로 작동하지만, 만약 오류가 나거나 실행이 원활히 되지 않을 경우에는 문의 바랍니다.
https://discord.gg/4SkaEJ3ub8
