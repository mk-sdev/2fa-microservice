A microservice for 2FA using TOTP written in Flask.

.env file structure:

```
JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=
JWT_2FA_SECRET=
DATABASE_URL=
TOTP_ENCRYPTION_KEY=
PEPPER=
```