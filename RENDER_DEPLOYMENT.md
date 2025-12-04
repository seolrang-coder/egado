# Render.com 배포 가이드

## 🚀 빠른 시작

### 1단계: GitHub에 코드 푸시

```bash
git add .
git commit -m "Render.com 배포 준비 완료"
git push origin main
```

### 2단계: Render.com에서 배포

1. **Render.com 가입**
   - https://render.com 접속
   - GitHub 계정으로 가입 (권장)

2. **새 Blueprint 생성**
   - Dashboard → "New +" → "Blueprint"
   - GitHub 저장소 선택
   - Render가 자동으로 `render.yaml` 파일을 인식

3. **환경 변수 확인**
   - `render.yaml`에 설정된 환경 변수들이 자동으로 적용됨
   - `SESSION_SECRET`은 자동 생성됨
   - `FRONTEND_URL`은 수동으로 추가 필요:
     ```
     FRONTEND_URL=https://your-netlify-site.netlify.app
     ```

4. **배포 시작**
   - "Apply" 클릭
   - 배포 완료까지 약 5-10분 소요

5. **백엔드 URL 확인**
   - 배포 완료 후 제공되는 URL 확인
   - 예: `https://union-site-backend.onrender.com`

## 📋 설정 상세

### render.yaml 구조

```yaml
services:
  - type: web
    name: union-site-backend
    env: node
    plan: free
    region: singapore
    buildCommand: cd backend && npm install
    startCommand: cd backend && npm start
    envVars:
      - key: NODE_ENV
        value: production
      - key: SESSION_SECRET
        generateValue: true
    disk:
      name: union-site-disk
      mountPath: /opt/render/project/src/backend
      sizeGB: 1
```

### 환경 변수 설명

| 변수명 | 설명 | 필수 | 기본값 |
|--------|------|------|--------|
| `NODE_ENV` | 실행 환경 | ✅ | `production` |
| `SESSION_SECRET` | 세션 암호화 키 | ✅ | 자동 생성 |
| `FRONTEND_URL` | 프론트엔드 URL (CORS용) | ⚠️ | 없음 |
| `ALLOWED_ORIGINS` | 추가 허용 origin (쉼표 구분) | ❌ | 없음 |
| `PORT` | 서버 포트 | ❌ | Render 자동 제공 |

## 🔧 수동 설정 방법

`render.yaml`을 사용하지 않는 경우:

1. **Web Service 생성**
   - "New +" → "Web Service"
   - GitHub 저장소 연결

2. **기본 설정**
   - **Name**: `union-site-backend`
   - **Environment**: `Node`
   - **Region**: `Singapore` (한국과 가까움)
   - **Branch**: `main` (또는 `master`)

3. **빌드 및 시작 명령어**
   - **Build Command**: `cd backend && npm install`
   - **Start Command**: `cd backend && npm start`

4. **환경 변수 추가**
   ```
   NODE_ENV=production
   SESSION_SECRET=생성한-랜덤-문자열
   FRONTEND_URL=https://your-netlify-site.netlify.app
   ```

5. **Disk 추가** (중요!)
   - "Add Disk" 클릭
   - **Name**: `union-site-disk`
   - **Mount Path**: `/opt/render/project/src/backend`
   - **Size**: 1GB (무료 플랜 최대)

## 🔗 프론트엔드 연결

### 방법 1: Netlify 프록시 (권장)

`netlify.toml` 파일 수정:

```toml
[[redirects]]
  from = "/api/*"
  to = "https://union-site-backend.onrender.com/api/:splat"
  status = 200
  force = true
  headers = {X-From = "Netlify"}
```

### 방법 2: 프론트엔드 코드 수정

모든 HTML 파일에서 API 호출을 백엔드 URL로 변경:

```javascript
// 변경 전
fetch('/api/user', { credentials: 'include' })

// 변경 후
fetch('https://union-site-backend.onrender.com/api/user', { 
  credentials: 'include' 
})
```

## ⚠️ 주의사항

### 1. Render 무료 플랜 제한

- **Sleep 모드**: 15분간 요청이 없으면 서비스가 sleep 상태가 됨
- **첫 요청 지연**: Sleep 상태에서 깨어나는 데 30초~1분 소요
- **해결 방법**:
  - 유료 플랜 사용 ($7/월부터)
  - 외부 서비스로 주기적 ping (UptimeRobot 등)

### 2. 데이터베이스

- SQLite 파일은 Render Disk에 저장됨
- 재배포 시에도 데이터 유지됨
- 첫 배포 후 관리자 계정을 수동으로 생성해야 함

### 3. 파일 업로드

- 업로드된 파일은 Render Disk에 저장됨
- Disk 용량 제한 확인 (무료 플랜: 1GB)
- 대용량 파일은 클라우드 스토리지 사용 권장

### 4. CORS 설정

- `FRONTEND_URL` 환경 변수에 Netlify 사이트 URL 설정 필수
- 여러 도메인 허용 시 `ALLOWED_ORIGINS` 사용

## 🐛 문제 해결

### 배포 실패

1. **빌드 로그 확인**
   - Render Dashboard → "Logs" 탭
   - 에러 메시지 확인

2. **일반적인 문제**
   - `npm install` 실패 → `package.json` 확인
   - 포트 에러 → `PORT` 환경 변수 확인 (설정 불필요)
   - 경로 에러 → `buildCommand`와 `startCommand` 확인

### API 요청 실패

1. **CORS 에러**
   - `FRONTEND_URL` 환경 변수 확인
   - 브라우저 콘솔에서 에러 메시지 확인

2. **연결 실패**
   - 백엔드 URL이 올바른지 확인
   - Render 서비스가 실행 중인지 확인 (sleep 상태일 수 있음)

### 세션/쿠키 문제

1. **쿠키가 저장되지 않음**
   - `sameSite: 'none'` 설정 확인 (프로덕션)
   - `secure: true` 설정 확인 (HTTPS 필수)
   - 브라우저 쿠키 설정 확인

## 📊 모니터링

### 로그 확인

- Render Dashboard → "Logs" 탭
- 실시간 로그 확인 가능
- 에러 발생 시 즉시 확인 가능

### 메트릭

- 무료 플랜: 기본 메트릭 제공
- 유료 플랜: 상세 메트릭 및 알림 기능

## 🔄 업데이트 배포

코드 변경 후 GitHub에 푸시하면 자동으로 재배포됩니다:

```bash
git add .
git commit -m "업데이트 내용"
git push origin main
```

Render가 자동으로 변경사항을 감지하고 재배포를 시작합니다.

## 💰 비용

- **무료 플랜**: 
  - Sleep 모드 (15분 비활성 시)
  - 1GB Disk
  - 기본 메트릭

- **Starter 플랜** ($7/월):
  - 항상 활성 상태
  - 10GB Disk
  - 상세 메트릭

- **Standard 플랜** ($25/월):
  - 더 많은 리소스
  - 자동 스케일링

## 📚 추가 자료

- [Render 공식 문서](https://render.com/docs)
- [Node.js 배포 가이드](https://render.com/docs/deploy-node-express-app)
- [Disk 사용 가이드](https://render.com/docs/disks)

