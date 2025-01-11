package tweet_my_pet.tweet_my_pet_backend.service;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.netty.handler.timeout.TimeoutException;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tweet_my_pet.tweet_my_pet_backend.dto.AuthCodeVerificationRequestDto;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.dto.ChangePasswordDto;
import tweet_my_pet.tweet_my_pet_backend.dto.PetDto;
import tweet_my_pet.tweet_my_pet_backend.dto.UserDto.FetchUserResponse;

import tweet_my_pet.tweet_my_pet_backend.entity.Pet;
import tweet_my_pet.tweet_my_pet_backend.entity.SearchHistory;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Reservation;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;

import tweet_my_pet.tweet_my_pet_backend.exception.AuthException.*;
import tweet_my_pet.tweet_my_pet_backend.exception.AuthExpireException;
import tweet_my_pet.tweet_my_pet_backend.exception.AuthInvalidException;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.NoApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.KakaoApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.NaverApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.PetRepository;

import tweet_my_pet.tweet_my_pet_backend.security.JwtTokenProvider;

import tweet_my_pet.tweet_my_pet_backend.exception.DuplicateResourceException;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
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
    private final KakaoApiUserLoginRepository kakaoApiUserLoginRepository;
    private final NaverApiUserLoginRepository naverApiUserLoginRepository;
    private final PetRepository petRepository;

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

    public boolean isExistsPhoneNumber(AuthCodeVerificationRequestDto.CreateIdAuthCodeVerificationRequest authCodeVerificationRequestDto) {
        return usersRepository.existsByUserPhoneNumberAndUserName(authCodeVerificationRequestDto.phoneNumber(),authCodeVerificationRequestDto.userName());
    }

    public boolean isExistsPhoneNumberAndEmail(AuthCodeVerificationRequestDto.CreatePasswordAuthCodeVerificationRequest authCodeVerificationRequestDto) {
        return usersRepository.existsByUserPhoneNumberAndUserNameAndUserEmail(authCodeVerificationRequestDto.phoneNumber(),authCodeVerificationRequestDto.userName(),authCodeVerificationRequestDto.userEmail());
    }

    /**
     * 인증 관련
     */
    private Map<String, String> authCodeStore = new HashMap<>();
    private Map<String, Instant> authCodeTimeStore = new HashMap<>();

    private Map<String, String> passwordTokenStore = new HashMap<>();
    private Map<String, Instant> passwordTokenTimeStore = new HashMap<>();

    /**
     * 인증 코드 생성
     * @param phoneNumber
     */
    public String generateAuthCode(String phoneNumber) {
        // 6자리 인증 코드 생성
        String authCode = String.format("%06d", new Random().nextInt(999999));
        authCodeStore.put(phoneNumber, authCode);
        Instant now = Instant.now();
        authCodeTimeStore.put(phoneNumber, now);
        log.info("인증번호: {}", authCode);
        return authCode;
    }

    /**
     * 인증 코드 확인
     * @param phoneNumber
     * @param authCode
     */
    public boolean verifyAuthCode(String phoneNumber, String authCode) {
        String storedAuthCode = authCodeStore.get(phoneNumber);
        Instant now = Instant.now();
        Instant start = authCodeTimeStore.get(phoneNumber);
        if(start==null){
            log.error("인증번호 확인 실패: 인증번호 만료");
            throw new AuthExpireException("인증번호 만료");
        }
        Duration duration = Duration.between(start, now);
        long seconds = duration.toSeconds();
        if(seconds>=300){
            authCodeTimeStore.remove(phoneNumber);
            log.error("인증번호 확인 실패: 인증번호 만료");
            throw new AuthExpireException("인증번호 만료");
        }

        // 인증번호가 동일하면 authCodeStore에서 지우고 true 반환
        if (authCode.equals(storedAuthCode)) {
            authCodeStore.remove(phoneNumber);
            authCodeTimeStore.remove(phoneNumber);
            log.info("인증번호 확인 성공");
            return true;
        } else {
            log.error("인증번호 확인 실패: 인증번호 불일치");
            throw new AuthInvalidException("인증번호 불일치");
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
            passwordTokenTimeStore.put(token,Instant.now());
            Instant now = Instant.now();
            authCodeTimeStore.put(token, now);
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
        Instant now = Instant.now();
        Instant start = passwordTokenTimeStore.get(token);

        Duration duration = Duration.between(start, now);
        long seconds = duration.toSeconds();
        if(seconds>=300){
            passwordTokenTimeStore.remove(phoneNumber);
            log.error("토큰 확인 실패: 토큰 만료");
            throw new AuthExpireException("토큰 만료");
        }
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

    /**
     * 토큰으로 유저 정보, 펫 정보 조회
     * @param token
     * @return
     */
    public FetchUserResponse validateToken(String token){
        User user;
        Pet pet;
        if(jwtTokenProvider.validateToken(token)){
            Long userId = Long.parseLong(jwtTokenProvider.getUserIdFromToken(token));
            String loginType = "NoAPI";
            // 데이터베이스에서 사용자 정보 조회
            user = usersRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if(!Optional.empty().equals(kakaoApiUserLoginRepository.findById(userId))){
                loginType = "Kakao";
            }
            else if(!Optional.empty().equals(naverApiUserLoginRepository.findById(userId))){
                loginType = "Naver";
            }

            pet = petRepository.findByPetId(user.getPet().getPetId());

            return FetchUserResponse.builder()
                    .userId(user.getUserId())
                    .pet(
                            PetDto.builder()
                            .petBirth(pet.getPetBirth())
                            .petGender(pet.getPetGender())
                            .petId(pet.getPetId())
                            .petName(pet.getPetName())
                            .petBreed(pet.getPetBreed())
                            .petSize(pet.getPetSize())
                        .build()
                    )
                    .userName(user.getUserName())
                    .userPhoneNumber(user.getUserPhoneNumber())
                    .userEmail(user.getUserEmail())
                    .reservations(user.getReservations())
                    .loginType(loginType)
                    .build();
        }
        else{
            throw new UsernameNotFoundException("Invalid token");
        }
    }
}
