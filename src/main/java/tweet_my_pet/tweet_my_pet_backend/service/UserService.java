package tweet_my_pet.tweet_my_pet_backend.service;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.dto.ChangePasswordDto;
import tweet_my_pet.tweet_my_pet_backend.entity.SearchHistory;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.exception.DuplicateResourceException;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;
import tweet_my_pet.tweet_my_pet_backend.security.JwtTokenProvider;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.repository.NoApiUserLoginRepository;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

/**
 * 사용자 서비스
 * @since 24.10.26
 * @latest 24.10.26
 * @author 권민지
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final NoApiUserLoginRepository noApiUserLoginRepository;

    /**
     * 회원가입
     * @param signupRequestDto
     */
    @Transactional
    public NoApiUserLogin signUp(SignupRequestDto signupRequestDto) {
        // 중복 아이디 체크
        if (noApiUserLoginRepository.existsByLoginId(signupRequestDto.getLoginId())) {
            throw new DuplicateResourceException("이미 존재하는 아이디입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        // 회원 정보 생성
        User user = User.builder()
                .userName(signupRequestDto.getName())
                .userPhoneNumber(signupRequestDto.getPhoneNumber())
                .userEmail(signupRequestDto.getEmail())
                .build();

        usersRepository.save(user);

        // 회원가입 요청 정보로 사용자 생성 (비밀번호 암호화)
        NoApiUserLogin noApiUserLogin = NoApiUserLogin.builder()
                .loginId(signupRequestDto.getLoginId())
                .password(encodedPassword)
                .user(user)
                .build();

        return noApiUserLoginRepository.save(noApiUserLogin);
    }

    /**
     * 로그인
     */
    public boolean login(String LoginId, String password) {
        // 아이디 존재 여부 확인
        if (!noApiUserLoginRepository.existsByLoginId(LoginId)) {
            log.error("로그인 실패: 존재하지 않는 아이디");
            return false;
        }

        // 비밀번호 일치 여부 확인 (암호화된 비밀번호 비교)
        NoApiUserLogin noApiUserLogin = noApiUserLoginRepository.findByLoginId(LoginId);
        boolean matches = passwordEncoder.matches(password, noApiUserLogin.getPassword());
        if (!matches) {
            log.error("로그인 실패: 비밀번호 불일치");
            return false;
        }

        log.info("로그인 성공");
        return true;
    }

    /**
     * 전화번호 존재여부 확인
     */
    public void existsByPhoneNumber(String phoneNumber) {
        if (usersRepository.existsByPhoneNumber(phoneNumber)) {
            throw new DuplicateResourceException("이미 존재하는 전화번호입니다.");
        }
    }

    /**
     * 인증 관련
     */
    private Map<String, String> authCodeStore = new HashMap<>();
    private Map<String, String> passwordTokenStore = new HashMap<>();

    /**
     * 인증 코드 생성
     * @param phoneNumber
     */
    public String generateAuthCode(String phoneNumber) {
        // 6자리 인증 코드 생성
        String authCode = String.format("%06d", new Random().nextInt(999999));
        authCodeStore.put(phoneNumber, authCode);
        log.info("인증번호: {}", authCode);
        return authCode;
    }

    /**
     * 인증 코드 확인
     * @param phoneNumber
     * @param authCode
     */
    public boolean verifyAuthCode(String phoneNumber, String authCode) {
        String key = "{\"phoneNumber\":\"" + phoneNumber + "\"}";
        String storedAuthCode = authCodeStore.get(key);

        // 인증번호가 동일하면 authCodeStore에서 지우고 true 반환
        if (authCode.equals(storedAuthCode)) {
            authCodeStore.remove(phoneNumber);
            log.info("인증번호 확인 성공");
            return true;
        } else {
            log.error("인증번호 확인 실패: 인증번호 불일치");
            return false;
        }
    }
    public static String generateRandomStr(int length, boolean isUpperCase) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
        }
        return isUpperCase ? sb.toString().toUpperCase() : sb.toString().toLowerCase();
    }
    public String storeToken(String phoneNumber) {
        String token = null;
        try {
            token = generateRandomStr(32, true);
            log.info("토큰 할당:"+token);
            log.info("토큰 할당:"+phoneNumber);
            passwordTokenStore.put(token,phoneNumber);
            log.info("토큰 할당 데이터:"+passwordTokenStore.get(token));
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return token;
    }
    public boolean verifyToken(ChangePasswordDto changePasswordDto) {
        String token = changePasswordDto.getToken();
        String phoneNumber = changePasswordDto.getPhoneNumber();
        String storedPhoneNumber = passwordTokenStore.get(token);
        if(storedPhoneNumber==null||storedPhoneNumber.isEmpty()){
            log.info("토근 인증 정보가 없습니다");
            return false;
        }
        if(storedPhoneNumber.equals(phoneNumber)) {
            log.info("토근 인증 성공");
            passwordTokenStore.remove(token);
            return true;
        }
        return false;
    }
    public boolean updatePassword(ChangePasswordDto changePasswordDto) {
        String phoneNumber = changePasswordDto.getPhoneNumber();
        String password = changePasswordDto.getPassword();
        log.info("패스워드 업데이트");
        String encodedPassword = passwordEncoder.encode(password);
        if(noApiUserLoginRepository.updateNoApiLoginUserPasswordByPhoneNumber(phoneNumber,encodedPassword)>0){
            log.info("패스워드 업데이트 성공");
            return true;
        }

        log.info("패스워드 업데이트 실패");
        return false;
    }

    /**
     * 유저 전화번호로 아이디 확인
     * @param phoneNumber
     */
    public String getUserLoginId(String phoneNumber) {
        String userName = noApiUserLoginRepository.findLoginIdByPhoneNumber(phoneNumber);
        if(userName!=null){
            return userName;
        }
        return null;
    }
}
