package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.service.KakaoService;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoUserInfo;
import org.springframework.beans.factory.annotation.Value;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth/kakao")
@CrossOrigin(origins = "*")
public class KakaoOauthRestController {

    private static final Logger logger = LoggerFactory.getLogger(KakaoOauthRestController.class);
    private final KakaoService kakaoService;

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.redirect_uri}")
    private String redirectUri;
    // 카카오 로그인 링크 반환
    @GetMapping("/login")
    public ResponseEntity<String> loginPage() {
        String location = "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id="
                + clientId + "&redirect_uri=" + redirectUri;
        logger.info("login 호출됨");
        return ResponseEntity.ok(location);
    }

    // 카카오 콜백 처리 및 사용자 정보 저장
    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam("code") String code) {
        try {
            logger.info("Kakao OAuth callback 호출됨, code: {}", code);

            // Access Token 가져오기
            String accessToken = kakaoService.getAccessToken(code);

            // 사용자 정보 가져오기
            KakaoUserInfo userInfo = kakaoService.getUserInfo(accessToken);

            // 사용자 정보를 확인하고 로그 출력
            if (userInfo != null && userInfo.getKakaoAccount() != null) {
                logger.info("Kakao ID: {}", userInfo.getId());
                logger.info("Kakao Nickname: {}", userInfo.getKakaoAccount().getProfile().getNickname());
                logger.info("Kakao Email: {}", userInfo.getKakaoAccount().getEmail());

                // 사용자 정보를 DB에 저장
                kakaoService.saveOrUpdateUser(userInfo);
            } else {
                logger.error("User info is null or incomplete.");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }

            // 리디렉션 설정
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectUri));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        } catch (Exception e) {
            logger.error("Error during Kakao OAuth callback: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestParam("accessToken") String accessToken) {
        try {
            kakaoService.logout(accessToken); // KakaoService의 로그아웃 메서드 호출
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            logger.error("Error during logout: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
