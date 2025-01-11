package tweet_my_pet.tweet_my_pet_backend.restController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.dto.AuthCodeVerificationRequestDto;
import tweet_my_pet.tweet_my_pet_backend.dto.ChangePasswordDto;
import tweet_my_pet.tweet_my_pet_backend.dto.LoginRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.dto.UserDto.FetchUserResponse;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.exception.DuplicateResourceException;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;
import tweet_my_pet.tweet_my_pet_backend.security.JwtTokenProvider;
import tweet_my_pet.tweet_my_pet_backend.service.UserService;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 회원가입, 로그인 rest controller
 * @since 24.10.26
 * @latest 24.11.02
 * @author 권민지
 */
@Slf4j
@RestController
@CrossOrigin(origins = "${server.cross-origin-url}, ${server.origin-url}")
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserRestController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final UsersRepository usersRepository;

    /**
     * 회원가입 요청 api
     * @param signupRequestDto
     */
    @Tag(name = "auth", description = "로그인, 회원가입")
    @Operation(summary = "회원가입")
    @Parameter(name = "signupRequestDto", description = "회원가입 유저 정보", required = true)
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@Valid @RequestBody SignupRequestDto signupRequestDto, HttpServletRequest request) {
        try {
            NoApiUserLogin savedUser = userService.signUp(signupRequestDto);
            return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
        } catch (DuplicateResourceException e) {
            log.error("Failed to sign up: {}", e.getMessage());
            return new ResponseEntity<>("중복 아이디 존재", HttpStatus.CONFLICT);
        } catch (Exception e) {
            log.error("회원가입 실패: {}", e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 로그인 api
     * @param loginRequest
     */
    @Tag(name = "auth", description = "로그인, 회원가입")
    @Operation(summary = "로그인")
    @Parameter(name = "loginId", description = "아이디", required = true)
    @Parameter(name = "password", description = "비밀번호", required = true)
    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            if (userService.login(loginRequest.getLoginId(), loginRequest.getPassword())) {
                // 로그인 성공시 토큰 생성 및 반환
                String token = jwtTokenProvider.generateToken(loginRequest.getLoginId());

                if (token == null) {
                    return new ResponseEntity<>("토큰 생성 실패", HttpStatus.BAD_REQUEST);
                }
                return new ResponseEntity<>(token, HttpStatus.OK);
            } else {
                return new ResponseEntity<>("로그인 실패", HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            log.error("로그인 실패: {}", e.getMessage());
            return new ResponseEntity<>("로그인 실패", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 전화번호로 인증 코드 전송 api
     * @param phoneNumber
     */
    @Tag(name = "auth", description = "로그인, 회원가입")
    @Operation(summary = "전화번호 인증코드 전송")
    @Parameter(name = "phoneNumber", description = "전화번호", required = true)
    @PostMapping("/send-auth-code")
    public ResponseEntity<String> sendAuthCode(@RequestBody String phoneNumber) {
        try {
            // 전화번호 존재여부 확인
            userService.existsByPhoneNumber(phoneNumber);
            // 인증 코드 생성 및 전송
            userService.generateAuthCode(phoneNumber);

            return new ResponseEntity<>("인증번호 전송 성공", HttpStatus.OK);
        } catch (DuplicateResourceException e) {
            log.error("Failed to send auth code: {}", e.getMessage());
            return new ResponseEntity<>("중복 전화번호 존재", HttpStatus.CONFLICT);
        } catch (Exception e) {
            log.error("인증번호 전송 실패: {}", e.getMessage());
            return new ResponseEntity<>("인증번호 전송 실패", HttpStatus.BAD_REQUEST);
        }

    }

    /**
     * 인증 코드 검증 api
     * @param requestDto
     */
    @Tag(name = "auth", description = "로그인, 회원가입")
    @Operation(summary = "인증코드 검증")
    @Parameter(name = "phoneNumber", description = "전화번호", required = true)
    @Parameter(name = "authCode", description = "인증코드", required = true)
    @PostMapping("/verify-auth-code")
    public ResponseEntity<String> verifyAuthCode(@RequestBody AuthCodeVerificationRequestDto requestDto) {
        if (userService.verifyAuthCode(requestDto.getPhoneNumber(), requestDto.getAuthCode())) {
            return new ResponseEntity<>("인증 성공", HttpStatus.OK);
        } else {
            return new ResponseEntity<>("인증 실패", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 아이디 찾기 api 인증번호 전송
     * @param phoneNumber
     */
    @Parameter(name = "PhoneNumber", description = "전화번호", required = true)
    @Parameter(name = "Name", description = "이름", required = true)
    @PostMapping("/send-find-auth-code")
    public ResponseEntity<String> findLoginId(@RequestBody String phoneNumber) {
        try {
            // 전화번호 존재여부 확인
            userService.existsByPhoneNumber(phoneNumber);
            // 인증 코드 생성 및 전송
            userService.generateAuthCode(phoneNumber);

            return new ResponseEntity<>("인증번호 전송 성공", HttpStatus.OK);
        } catch (DuplicateResourceException e) {
            log.error("Failed to send auth code: {}", e.getMessage());
            return new ResponseEntity<>("중복 전화번호 존재", HttpStatus.CONFLICT);
        } catch (Exception e) {
            log.error("인증번호 전송 실패: {}", e.getMessage());
            return new ResponseEntity<>("인증번호 전송 실패", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 인증 코드 검증 api
     * @param requestDto
     */
    @Tag(name = "auth", description = "로그인 아이디 찾기 인증코드 검증")
    @Operation(summary = "인증코드 검증")
    @Parameter(name = "phoneNumber", description = "전화번호", required = true)
    @Parameter(name = "authCode", description = "인증코드", required = true)
    @PostMapping("/verify-findId-auth-code")
    public ResponseEntity<String> verifyFindIdCode(@RequestBody AuthCodeVerificationRequestDto requestDto) {
        if (userService.verifyAuthCode(requestDto.getPhoneNumber(), requestDto.getAuthCode())) {

            return new ResponseEntity<>(userService.getUserLoginId(requestDto.getPhoneNumber()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>("인증 실패", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 인증 코드 검증 api
     * @param requestDto
     */
    @Tag(name = "auth", description = "비밀번호 변경 인증코드 검증")
    @Operation(summary = "비밀번호 변경 인증코드 검증")
    @Parameter(name = "phoneNumber", description = "전화번호", required = true)
    @Parameter(name = "authCode", description = "인증코드", required = true)
    @PostMapping("/verify-findPassword-auth-code")
    public ResponseEntity<String> verifyFindPasswordCode(@RequestBody AuthCodeVerificationRequestDto requestDto) {
        if (userService.verifyAuthCode(requestDto.getPhoneNumber(), requestDto.getAuthCode())) {
            String token = userService.storeToken(requestDto.getPhoneNumber());
            return new ResponseEntity<>(token, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("인증 실패", HttpStatus.BAD_REQUEST);
        }
    }

    @Tag(name = "auth", description = "비밀번호 변경")
    @Operation(summary = "비밀번호 변경")
    @Parameter(name = "token", description = "변경 토큰", required = true)
    @Parameter(name = "phoneNumber", description = "전화번호", required = true)
    @Parameter(name = "password", description = "비밀번호", required = true)
    @PostMapping("/changePassword")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordDto requestDto) {
        if(userService.verifyToken(requestDto)) {
            if(userService.updatePassword(requestDto))
                return new ResponseEntity<>("변경 성공", HttpStatus.OK);
            else
                return new ResponseEntity<>("인증 실패", HttpStatus.BAD_REQUEST);
        } else {
            return new ResponseEntity<>("인증 실패", HttpStatus.BAD_REQUEST);
    @Tag(name = "auth", description = "유저 정보 조회")
    @Operation(summary = "유저 정보 조회")
    @GetMapping("/user/profile")
    public ResponseEntity<ResponseDto<FetchUserResponse>> getUserProfile(@RequestHeader("Authorization") String authorizationHeader) {
        try {

            // Authorization 헤더에서 토큰 추출
            String token = authorizationHeader.replace("Bearer ", "");
            FetchUserResponse userResponse = userService.validateToken(token);
            // 토큰 검증 및 사용자 ID 추출
            if (!jwtTokenProvider.validateToken(token)) {
                return new ResponseEntity<>(
                        new ResponseDto<>(ResponseDto.Status.FAILURE, "유저 정보 조회 실패",null),
                        HttpStatus.UNAUTHORIZED
                );
            }


            // 사용자 정보 반환
            return new ResponseEntity<>(
                    new ResponseDto<>(ResponseDto.Status.SUCCESS, "유저 정보 조회 성공",userResponse),
                    HttpStatus.OK
            );
        } catch (Exception e) {
            log.error("로그인 토큰 인증 실패: {}", e.getMessage());
            return new ResponseEntity<>(
                    new ResponseDto<>(ResponseDto.Status.FAILURE, "유저 정보 조회 실패:"+e.getMessage().toString(),null),
                    HttpStatus.UNAUTHORIZED
            );
        }
    }

}
