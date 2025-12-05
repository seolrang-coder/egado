# 배포 가이드

## ⚠️ 중요 사항

현재 프로젝트는 **프론트엔드(정적 HTML)**와 **백엔드(Express 서버)**로 구성되어 있습니다.

**Netlify는 정적 사이트만 호스팅**하므로, 백엔드는 별도로 호스팅해야 합니다.

## 배포 전략

### 옵션 1: 프론트엔드만 Netlify, 백엔드는 별도 호스팅 (권장)

1. **프론트엔드 (Netlify)**
   - 정적 HTML 파일들을 Netlify에 배포
   - API 요청은 백엔드 서버로 프록시

2. **백엔드 호스팅 옵션**
   - **Render** (https://render.com) - ✅ 설정 완료
   - **Railway** (https://railway.app)
   - **Heroku** (유료)
   - **AWS/Google Cloud** 등

### 옵션 2: Netlify Functions로 백엔드 변환

- Express 서버를 Netlify Functions로 변환 (작업량 많음)
- SQLite를 서버리스 DB로 변경 필요

## 배포 단계

### 1. 백엔드 배포 (Render.com) ✅

**방법 1: render.yaml 사용 (권장)**

1. Render.com에 가입 (https://render.com)
2. Dashboard에서 "New +" → "Blueprint" 선택
3. GitHub 저장소 연결
4. Render가 자동으로 `render.yaml` 파일을 인식하여 설정 적용
5. 환경 변수는 `render.yaml`에 이미 설정되어 있음 (SESSION_SECRET은 자동 생성)
6. 배포 시작 후 백엔드 URL 확인 (예: `https://union-site-backend.onrender.com`)

**방법 2: 수동 설정**

1. Render.com에 가입
2. Dashboard에서 "New +" → "Web Service" 선택
3. GitHub 저장소 연결
4. 설정:
   - **Name**: `union-site-backend`
   - **Environment**: `Node`
   - **Build Command**: `cd backend && npm install`
   - **Start Command**: `cd backend && npm start`
   - **Root Directory**: (비워두기 - 루트에서 시작)
5. 환경 변수 추가:
   ```
   NODE_ENV=production
   SESSION_SECRET=랜덤한-긴-문자열-생성
   FRONTEND_URL=https://your-netlify-site.netlify.app
   ```
   > 💡 **SESSION_SECRET 생성 방법**: 
   > - 터미널에서 `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` 실행
   > - 또는 온라인 랜덤 문자열 생성기 사용
6. **Disk 추가** (SQLite DB와 업로드 파일 저장용):
   - "Add Disk" 클릭
   - Name: `union-site-disk`
   - Mount Path: `/opt/render/project/src/backend`
   - Size: 1GB (무료 플랜)
7. 배포 시작 후 백엔드 URL 확인

**⚠️ 중요 사항:**
- Render 무료 플랜은 15분간 요청이 없으면 서비스가 sleep 상태가 됩니다
- 첫 요청 시 깨어나는 데 약 30초~1분 소요됩니다
- 프로덕션 환경에서는 유료 플랜 사용 권장

### 2. 프론트엔드 배포 (Netlify)

1. Netlify에 가입 및 새 사이트 생성
2. GitHub 저장소 연결
3. 빌드 설정:
   - Build command: (비워두기)
   - Publish directory: `.` (루트)
4. 환경 변수 설정:
   ```
   NETLIFY_BACKEND_URL=https://your-backend.railway.app
   ```

### 3. 프론트엔드 API 엔드포인트 수정

현재 프론트엔드는 상대 경로(`/api/*`)로 요청을 보내고 있습니다.
백엔드가 별도 도메인에 호스팅되면 두 가지 방법이 있습니다:

**방법 1: Netlify 프록시 사용 (권장)**
- `netlify.toml`의 redirects 설정 활용
- 프론트엔드 코드 수정 불필요
- 단, 백엔드 URL을 `netlify.toml`에 직접 입력해야 함

**방법 2: 프론트엔드 코드 수정**
- 모든 HTML 파일에서 `/api/`를 백엔드 URL로 변경
- 예: `fetch('/api/user')` → `fetch('https://your-backend.railway.app/api/user')`
- 더 유연하지만 모든 파일 수정 필요

### 4. CORS 설정 (백엔드) ✅

**이미 완료됨!** `backend/server.js`에 CORS 설정이 추가되어 있습니다.

**환경 변수로 프론트엔드 URL 설정:**
Render.com 대시보드에서 환경 변수 추가:
```
FRONTEND_URL=https://your-netlify-site.netlify.app
```

또는 여러 도메인 허용:
```
ALLOWED_ORIGINS=https://site1.netlify.app,https://site2.netlify.app
```

**로컬 개발 시:**
- 기본적으로 `http://localhost:3000`, `http://localhost:5000` 등이 허용됩니다
- 개발 환경에서는 모든 origin이 허용됩니다 (프로덕션에서만 필터링)

## 현재 상태 점검

### ✅ 완료된 항목
- `.gitignore` 파일 생성 (node_modules, app.db 등 제외)
- `netlify.toml` 설정 파일 생성 (정적 사이트 배포용)
- `render.yaml` 파일 생성 (Render.com 배포 설정)
- CORS 패키지 추가 및 설정 완료
- 세션 시크릿을 환경 변수로 변경 완료
- PORT를 환경 변수로 변경 완료 (Render 자동 지원)
- 배포 가이드 문서 작성

### ⚠️ 주의 사항

1. **데이터베이스**
   - SQLite 파일(`app.db`)은 Git에 포함하지 않음
   - Render 배포 시 빈 DB로 시작 (첫 배포 후 관리자 계정 생성 필요)
   - Render Disk에 저장되므로 재배포 시에도 데이터 유지됨

2. **파일 업로드**
   - `backend/public/uploads/` 폴더의 파일들은 Render Disk에 저장됨
   - 대용량 파일의 경우 클라우드 스토리지(S3, Cloudinary 등) 사용 권장

3. **API 엔드포인트**
   - 프론트엔드의 모든 `/api/*` 요청을 백엔드 URL로 변경하거나
   - Netlify 프록시 설정 활용

## 환경 변수 설정

### 백엔드 (Render.com)

**필수 환경 변수:**
```
NODE_ENV=production
SESSION_SECRET=랜덤한-긴-문자열 (render.yaml에서 자동 생성됨)
FRONTEND_URL=https://your-netlify-site.netlify.app
```

**선택적 환경 변수:**
```
ALLOWED_ORIGINS=https://site1.netlify.app,https://site2.netlify.app
```

**참고:**
- `PORT`는 Render가 자동으로 제공하므로 설정 불필요
- `SESSION_SECRET`은 `render.yaml`에서 `generateValue: true`로 설정되어 자동 생성됨

### 프론트엔드 (Netlify)
```
NETLIFY_BACKEND_URL=https://your-backend.onrender.com
```

또는 `netlify.toml`의 redirects 설정에서 백엔드 URL 직접 지정

## 문제 해결

### API 요청 실패
- CORS 설정 확인
- 백엔드 URL이 올바른지 확인
- 브라우저 콘솔에서 에러 확인

### 세션/쿠키 문제
- `sameSite` 설정 확인
- HTTPS 사용 필수 (Netlify는 기본 HTTPS)

### 데이터베이스 문제
- SQLite는 Render Disk에 저장되므로 재배포 시에도 유지됨
- 첫 배포 후 관리자 계정을 수동으로 생성해야 함
- 대용량 트래픽의 경우 PostgreSQL 등으로 마이그레이션 고려

### Render 서비스 Sleep 문제
- 무료 플랜은 15분간 요청이 없으면 sleep 상태가 됨
- 첫 요청 시 깨어나는 데 30초~1분 소요
- 해결 방법:
  - 유료 플랜 사용 (항상 활성 상태)
  - 외부 cron 서비스로 주기적 ping (예: UptimeRobot)

