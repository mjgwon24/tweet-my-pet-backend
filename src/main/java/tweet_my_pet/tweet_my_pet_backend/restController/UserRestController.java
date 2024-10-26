package tweet_my_pet.tweet_my_pet_backend.restController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.entity.Users;
import tweet_my_pet.tweet_my_pet_backend.service.UserService;

/**
 * 회원가입, 로그인 rest controller
 * @since 24.10.26
 * @latest 24.10.26
 * @author 권민지
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserRestController {

    private final UserService userService;

    /**
     * 회원가입 요청 api
     * @param signupRequestDto
     */
    @Tag(name = "auth", description = "로그인, 회원가입")
    @Operation(summary = "회원가입")
    @Parameter(name = "signupRequestDto", description = "회원가입 유저 정보", required = true)
    @PostMapping("/signup")
    public ResponseEntity<Users> signUp(@RequestBody SignupRequestDto signupRequestDto) {
        log.info("회원가입 요청: {}", signupRequestDto);
        Users savedUser = userService.signUp(signupRequestDto);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
    }
}
