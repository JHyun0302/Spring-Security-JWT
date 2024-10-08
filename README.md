# Spring Security JWT 실습

## 실습 목표
- 스프링 시큐리티 6 프레임워크를 활용하여 JWT 기반의 인증/인가를 구현하고 회원 정보 저장(영속성) MySQL 데이터베이스를 활용
- 서버는 API 서버 형태로 구축한다. (웹 페이지를 응답하는 것이 아닌 API 클라이언트 요청을 통해 데이터 응답만 확인함)

---
## 구현
- 인증 : 로그인
- 인가 : JWT를 통한 경로별 접근 권한
- 회원가입

---
## JWT 인증 방식 시큐리티 동작 원리
- 회원가입 : 내부 회원 가입 로직은 세션 방식과 JWT 방식의 차이가 없다.

![image](https://github.com/user-attachments/assets/1eced69d-6ac4-4b6b-80d7-5db880bec177)


- 로그인 (인증) : 로그인 요청을 받은 후 세션 방식은 서버 세션이 유저 정보를 저장하지만 JWT 방식은 토큰을 생성하여 응답한다.

![image](https://github.com/user-attachments/assets/cb64fd6f-d344-4b44-ad29-9d63fb8982fa)

- 경로 접근 (인가) : JWT Filter를 통해 요청의 헤더에서 JWT를 찾아 검증을하고 일시적 요청에 대한 Session을 생성한다. (생성된 세션은 요청이 끝나면 소멸됨)

![image](https://github.com/user-attachments/assets/6507377d-5844-4270-88b6-7552a1342f51)
