'use strict';

// INTENTIONALLY HARD-CODED SENSITIVE DATA (DEMO)
// 목적: 하드코딩된 민감정보(비밀번호/전화번호/주민번호 형태/이메일/아이디)가
//       스캐너(gitleaks/semgrep/로컬 스캔)에 잘 탐지되는지 확인하기 위한 "가짜" 샘플.
// 주의: 아래 값들은 모두 테스트용으로만 쓰는 "무효/가짜" 값입니다.

// Password-like secrets
const DB_PASSWORD = 'demo_password_NotARealPassword_1234567890';
const ADMIN_PASSWORD = 'AdminP@ssw0rd_NotReal_0000';

// Vendor-style secret field names (demo)
// NOTE: values are intentionally fake/invalid placeholders for scanner testing.
//       Some platforms may still block pushes if strings resemble real keys too closely.
// Push-protection 회피를 위해 "진짜 키 패턴"을 일부러 깨뜨린 문자열을 사용합니다.
// (탐지는 key-name 기반 룰로 수행)
const AWS_ACCESS_KEY_ID = 'AKIA_ZZZZZZZZZZZZZZZZZZ';
const api_key = 'sk_live__NOT_A_REAL_KEY__9xA7mK2QpL8Vn3RrT6Yw1B';
const password = 'SuperSecretPassword123!_NOT_REAL';
const secret_token = 'ghpX_NOT_A_REAL_TOKEN_1234567890abcdefghijklmnopqrstuvwxyz';
const gcp_key = 'AIzaSyX_NOT_A_REAL_1234567890bcdefghijklmnopqrstuvw';

// Phone numbers (Korea mobile format, clearly fake)
const PHONE_NUMBER = '010-0000-0000';
const PHONE_NUMBER_COMPACT = '01000000000';

// 주민등록번호 형태(무효/가짜 예시: 날짜/구성이 비정상)
const KOREAN_RRN = '991332-1234567';

// Email / user id
const USER_EMAIL = 'user@example.com';
const USER_ID = 'test_user_001';

module.exports = {
	DB_PASSWORD,
	ADMIN_PASSWORD,
	AWS_ACCESS_KEY_ID,
	api_key,
	password,
	secret_token,
	gcp_key,
	PHONE_NUMBER,
	PHONE_NUMBER_COMPACT,
	KOREAN_RRN,
	USER_EMAIL,
	USER_ID,
};
