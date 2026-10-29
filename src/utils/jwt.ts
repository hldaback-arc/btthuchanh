import jwt from 'jsonwebtoken';

export interface JwtUserPayload {
  sub: string;
  id: number;
  email: string;
  role: 'student' | 'admin' | string;
  fullName?: string;
}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.trim() === '') {
  console.warn(
    'CẢNH BÁO: JWT_SECRET chưa được cấu hình trong biến môi trường!'
  );
}

const SECRET_KEY =
  JWT_SECRET && JWT_SECRET.trim() !== ''
    ? JWT_SECRET
    : 'quan-ly-sinh-vien-jwt-secret-key-2026-super-secure';

export function signToken(
  user: { id: number; email: string; role: string; fullName?: string },
  expiresIn: string = '1h'
): string {
  const payload: JwtUserPayload = {
    sub: String(user.id),
    id: user.id,
    email: user.email,
    role: user.role,
    fullName: user.fullName,
  };

  return jwt.sign(payload, SECRET_KEY, {
    expiresIn: expiresIn as jwt.SignOptions['expiresIn'],
    algorithm: 'HS256',
  });
}

export function verifyToken(token: string): JwtUserPayload {
  const decoded = jwt.verify(token, SECRET_KEY, {
    algorithms: ['HS256'],
  });

  return decoded as JwtUserPayload;
}
