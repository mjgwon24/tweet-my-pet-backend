package tweet_my_pet.tweet_my_pet_backend.restController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoTokenResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoUserInfo;
import tweet_my_pet.tweet_my_pet_backend.service.KakaoService;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth/kakao")
@RequiredArgsConstructor
public class KakaoOauthRestController {

    private final KakaoService kakaoService;

    @PostMapping("/callback")
    public ResponseEntity<Map<String, String>> kakaoCallback(@RequestBody Map<String, String> requestBody) {
        String code = requestBody.get("code");
        if (code == null || code.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Authorization code is missing"));
        }

        try {
            // Access Token 요청 및 처리
            KakaoTokenResponse tokenResponse = kakaoService.getAccessToken(code);
            if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
                return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve access token"));
            }

            String accessToken = tokenResponse.getAccessToken();
            String refreshToken = tokenResponse.getRefreshToken();

            // 사용자 정보 조회 및 저장
            KakaoUserInfo userInfo = kakaoService.getUserInfo(tokenResponse);
            if (userInfo == null) {
                return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve user information"));
            }

            // 액세스 토큰 및 기타 정보를 클라이언트에 반환
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", tokenResponse.getAccessToken());
            response.put("refreshToken", tokenResponse.getRefreshToken());
            response.put("email", userInfo.getKakaoAccount().getEmail());
            response.put("nickname", userInfo.getKakaoAccount().getProfile().getNickname());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error in kakaoCallback: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    // 로그아웃 엔드포인트
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> kakaoLogout(@RequestBody Map<String, String> requestBody) {
        log.info("Received /logout request with body: {}", requestBody); // 요청 로그 추가
        String accessToken = requestBody.get("accessToken");
        log.info("Received AccessToken for logout: {}", accessToken);
        if (accessToken == null || accessToken.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Access token is missing"));
        }

        try {
            kakaoService.logout(accessToken);
            return ResponseEntity.ok(Map.of("message", "Logout successful"));
        } catch (Exception e) {
            log.error("Error in kakaoLogout: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Failed to logout"));
        }
    }
}