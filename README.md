# KeyAuth Control Panel — Railway Ready

ASP.NET Core .NET 8 + SQLite + JWT พร้อม UI โทนมืดและเอฟเฟกต์ดาวตกเต็มหน้าจอ

## Railway Variables (จำเป็น)

```env
OWNER_USERNAME=your_owner_username
OWNER_PASSWORD=your_strong_password
JWT_SECRET=put-a-long-random-secret-at-least-32-characters
```

แนะนำถ้าต้องการให้ SQLite อยู่ถาวรหลัง Redeploy:
1. เพิ่ม Railway Volume และ mount ที่ `/data`
2. เพิ่ม Variable:

```env
DATABASE_PATH=/data/keyauth.db
```

Railway จะกำหนด `PORT` ให้เอง โปรแกรมอ่านค่านี้อัตโนมัติและ bind ที่ `0.0.0.0` แล้ว

## Deploy Railway

โปรเจกต์มี `Dockerfile` และ `railway.toml` พร้อมใช้

### ผ่าน Railway CLI

```bash
railway login
railway init
railway up
```

หลัง deploy ไปที่ Service > Settings > Networking > Generate Domain

### ผ่าน GitHub
Push โฟลเดอร์นี้ขึ้น GitHub แล้วเลือก Deploy from GitHub Repo ใน Railway ได้เลย

## คำสั่งรันเว็บบนเครื่อง

### Windows CMD
```bat
set OWNER_USERNAME=admin
set OWNER_PASSWORD=your_password
set JWT_SECRET=change-this-to-a-long-random-secret-32chars
set PORT=8080
dotnet restore
dotnet run
```

### PowerShell
```powershell
$env:OWNER_USERNAME="admin"
$env:OWNER_PASSWORD="your_password"
$env:JWT_SECRET="change-this-to-a-long-random-secret-32chars"
$env:PORT="8080"
dotnet restore
dotnet run
```

เปิด `http://localhost:8080`

## Login
หน้าเว็บใช้เฉพาะบัญชี Owner จาก `OWNER_USERNAME` และ `OWNER_PASSWORD` แล้ว ไม่มีค่า username/password ฝังไว้ในหน้า Login
