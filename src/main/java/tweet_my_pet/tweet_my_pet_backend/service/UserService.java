package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.entity.Users;
import tweet_my_pet.tweet_my_pet_backend.exception.DuplicateResourceException;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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

    /**
     * 회원가입
     * @param signupRequestDto
     */
    @Transactional
    public Users signUp(SignupRequestDto signupRequestDto) {
        // 중복 아이디 체크
        if (usersRepository.existsByLoginId(signupRequestDto.getLoginId())) {
            throw new DuplicateResourceException("이미 존재하는 아이디입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        // 회원가입 요청 정보로 사용자 생성 (비밀번호 암호화)
        Users user = Users.builder()
                .loginId(signupRequestDto.getLoginId())
                .password(encodedPassword)
                .name(signupRequestDto.getName())
                .phoneNumber(signupRequestDto.getPhoneNumber())
                .build();

        return usersRepository.save(user);
    }

    /**
     * 로그인
     */
    public boolean login(String loginId, String password) {
        // 아이디 존재 여부 확인
        if (!usersRepository.existsByLoginId(loginId)) {
            log.error("로그인 실패: 존재하지 않는 아이디");
            return false;
        }

        // 비밀번호 일치 여부 확인 (암호화된 비밀번호 비교)
        Users user = usersRepository.findByLoginId(loginId);
        boolean matches = passwordEncoder.matches(password, user.getPassword());
        if (!matches) {
            log.error("로그인 실패: 비밀번호 불일치");
            return false;
        }

        // 로그인 성공시 세션 저장
        // ...
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
}
