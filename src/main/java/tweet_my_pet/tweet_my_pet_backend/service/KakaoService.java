package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // 트랜잭션 처리 임포트
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoUserInfo;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoTokenResponse;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class KakaoService {

    private static final Logger logger = LoggerFactory.getLogger(KakaoService.class);
    private final UsersRepository usersRepository;

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.redirect_uri}")
    private String redirectUri;

    @Value("${kakao.token_uri}")
    private String tokenUri;

    @Value("${kakao.user_info_uri}")
    private String userInfoUri;

    // Access Token 요청 메서드
    public String getAccessToken(String code) {
        WebClient webClient = WebClient.builder()
                .baseUrl(tokenUri)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();

        try {
            KakaoTokenResponse tokenResponse = webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .queryParam("grant_type", "authorization_code")
                            .queryParam("client_id", clientId)
                            .queryParam("redirect_uri", redirectUri)
                            .queryParam("code", code)
                            .build())
                    .retrieve()
                    .onStatus(status -> status.isError(), clientResponse -> {
                        logger.error("Error response while retrieving access token: {}", clientResponse.statusCode());
                        return Mono.error(new RuntimeException("Error while retrieving access token"));
                    })
                    .bodyToMono(KakaoTokenResponse.class)
                    .block();

            if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
                throw new RuntimeException("Failed to retrieve access token.");
            }
            return tokenResponse.getAccessToken();
        } catch (Exception e) {
            logger.error("Error while retrieving access token: {}", e.getMessage());
            throw new RuntimeException("Error while retrieving access token", e);
        }
    }

    // 사용자 정보 요청 메서드
    public KakaoUserInfo getUserInfo(String accessToken) {
        WebClient webClient = WebClient.builder()
                .baseUrl(userInfoUri)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();

        try {
            KakaoUserInfo userInfo = webClient.get()
                    .retrieve()
                    .onStatus(status -> status.isError(), clientResponse -> {
                        logger.error("Error response while retrieving user info: {}", clientResponse.statusCode());
                        return Mono.error(new RuntimeException("Error while retrieving user info"));
                    })
                    .bodyToMono(KakaoUserInfo.class)
                    .block();

            if (userInfo == null || userInfo.getKakaoAccount() == null) {
                throw new RuntimeException("Failed to retrieve user info.");
            }
            saveOrUpdateUser(userInfo); // 사용자 정보 저장 또는 업데이트
            return userInfo;
        } catch (Exception e) {
            logger.error("Error while retrieving user info: {}", e.getMessage());
            throw new RuntimeException("Error while retrieving user info", e);
        }
    }

    // 사용자 정보를 DB에 저장하거나 업데이트하는 메서드
    @Transactional // 트랜잭션 처리 추가
    public void saveOrUpdateUser(KakaoUserInfo userInfo) {

        log.info("saveOrUpdateUser 메서드가 호출되었습니다.");
        try {
            String kakaoId = String.valueOf(userInfo.getId());
            String email = userInfo.getKakaoAccount().getEmail();
            String nickname = userInfo.getKakaoAccount().getProfile().getNickname();
            String profileImageUrl = userInfo.getKakaoAccount().getProfile().getProfileImageUrl();

            // 사용자 정보가 이미 존재하는지 확인
            User existingUser = usersRepository.findByKakaoId(userId);
            if (existingUser == null) {
                // 새 사용자 저장
                User newUser = User.builder()
                        .userEmail(email)
                        .build();
                usersRepository.save(newUser);
                logger.info("새 사용자 저장: {}", email);
            } else {
                // 기존 사용자 정보 업데이트
                existingUser.setUserEmail(email);
                usersRepository.save(existingUser);
                logger.info("기존 사용자 업데이트: {}", email);
            }
        } catch (Exception e) {
            logger.error("Error while saving or updating user info: {}", e.getMessage());
        }
    }
    public void logout(String accessToken) {
        WebClient webClient = WebClient.builder()
                .baseUrl("https://kapi.kakao.com/v1/user/logout")
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();

        try {
            webClient.post()
                    .retrieve()
                    .onStatus(status -> status.isError(), clientResponse -> {
                        logger.error("Error response while logging out: {}", clientResponse.statusCode());
                        return Mono.error(new RuntimeException("Error while logging out"));
                    })
                    .bodyToMono(Void.class)
                    .block(); // 로그아웃 요청 실행
            logger.info("User logged out successfully");
        } catch (Exception e) {
            logger.error("Error while logging out: {}", e.getMessage());
        }
    }

}
