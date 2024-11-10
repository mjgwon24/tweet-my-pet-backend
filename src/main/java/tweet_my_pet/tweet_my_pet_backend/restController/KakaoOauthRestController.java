package tweet_my_pet.tweet_my_pet_backend.restController;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
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

    // 인증 코드로 액세스 토큰과 사용자 정보 조회 및 저장
    @PostMapping("/callback")
    public ResponseEntity<Map<String, String>> kakaoCallback(@RequestBody Map<String, String> requestBody) {
        String code = requestBody.get("code");
        if (code == null || code.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Authorization code is missing"));
        }

        try {
            // Access Token 획득
            String accessToken = kakaoService.getAccessToken(code);
            if (accessToken == null) {
                return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve access token"));
            }

            // 사용자 정보 조회 및 저장
            KakaoUserInfo userInfo = kakaoService.getUserInfo(accessToken);
            if (userInfo == null) {
                return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve user information"));
            }

            // 액세스 토큰을 클라이언트에 반환
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", accessToken);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error in kakaoCallback: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    // 로그아웃 엔드포인트
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> kakaoLogout(@RequestBody Map<String, String> requestBody) {
        String accessToken = requestBody.get("accessToken");
        if (accessToken == null || accessToken.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Access token is missing"));
        }

        try {
            kakaoService.logout(accessToken);
            return ResponseEntity.ok(Map.of("message", "Logout successful"));
        } catch (Exception e) {
            log.error("Error in kakaoLogout: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Failed to logout"));
        }
    }
}
