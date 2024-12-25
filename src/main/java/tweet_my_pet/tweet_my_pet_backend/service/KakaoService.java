package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoTokenResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoUserInfo;
import tweet_my_pet.tweet_my_pet_backend.entity.KakaoApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.Pet;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.KakaoApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.PetRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class KakaoService {

    private final UsersRepository usersRepository;
    private final KakaoApiUserLoginRepository kakaoApiUserLoginRepository;
    private final PetRepository petRepository;

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.redirect_uri}")
    private String redirectUri;

    @Value("${kakao.token_uri}")
    private String tokenUri;

    @Value("${kakao.user_info_uri}")
    private String userInfoUri;

    public KakaoTokenResponse getAccessToken(String code) {
        WebClient webClient = WebClient.builder()
                .baseUrl(tokenUri)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();

        try {
            return webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .queryParam("grant_type", "authorization_code")
                            .queryParam("client_id", clientId)
                            .queryParam("redirect_uri", redirectUri)
                            .queryParam("code", code)
                            .build())
                    .retrieve()
                    .bodyToMono(KakaoTokenResponse.class)
                    .block();
        } catch (Exception e) {
            log.error("Error while retrieving access token: {}", e.getMessage());
            throw new RuntimeException("Error while retrieving access token", e);
        }
    }

    public KakaoUserInfo getUserInfo(KakaoTokenResponse tokenResponse) {
        String accessToken = tokenResponse.getAccessToken();

        WebClient webClient = WebClient.builder()
                .baseUrl(userInfoUri)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();

        try {
            KakaoUserInfo userInfo = webClient.get()
                    .retrieve()
                    .bodyToMono(KakaoUserInfo.class)
                    .block();

            if (userInfo == null || userInfo.getKakaoAccount() == null) {
                throw new RuntimeException("Failed to retrieve user info.");
            }

            String phoneNumber = userInfo.getKakaoAccount().getPhoneNumber();
            if (phoneNumber == null || phoneNumber.isEmpty()) {
                phoneNumber = "010-0000-0000"; // 기본값
            }

            saveOrUpdateUser(userInfo, accessToken, tokenResponse.getRefreshToken(), phoneNumber);
            return userInfo;
        } catch (Exception e) {
            log.error("Error while retrieving user info: {}", e.getMessage());
            throw new RuntimeException("Error while retrieving user info", e);
        }
    }

    @Transactional
    public void saveOrUpdateUser(KakaoUserInfo userInfo, String accessToken, String refreshToken, String phoneNumber) {
        Long kakaoId = userInfo.getId();
        String nickname = userInfo.getKakaoAccount().getProfile().getNickname();
        String email = userInfo.getKakaoAccount().getEmail();
        email = (email == null || email.isEmpty()) ? "default_" + kakaoId + "@example.com" : email;

        User existingUser = usersRepository.findByUserEmail(email);

        if (existingUser != null) {
            updateExistingUserLogin(existingUser, kakaoId, accessToken, refreshToken, nickname, phoneNumber);
            return;
        }

        KakaoApiUserLogin kakaoApiUserLogin = kakaoApiUserLoginRepository.findByKakaoApiUserId(kakaoId);

        if (kakaoApiUserLogin == null) {
            User newUser = createNewUser(kakaoId, nickname, email, "medium", phoneNumber);
            createNewKakaoApiUserLogin(kakaoId, nickname, accessToken, refreshToken, newUser);
        } else {
            User user = kakaoApiUserLogin.getUser();
            updateExistingUserLogin(user, kakaoId, accessToken, refreshToken, nickname, phoneNumber);
        }
    }

    private Pet createNewPet(String petName, String petSizeString) {
        PetSizeType petSizeType;

        switch (petSizeString.toLowerCase()) {
            case "small":
                petSizeType = PetSizeType.small;
                break;
            case "medium":
                petSizeType = PetSizeType.medium;
                break;
            case "large":
                petSizeType = PetSizeType.big;
                break;
            default:
                throw new IllegalArgumentException("Unsupported pet size: " + petSizeString);
        }

        Pet newPet = Pet.builder()
                .petName(petName)
                .petSize(petSizeType)
                .build();

        return petRepository.save(newPet);
    }

    private User createNewUser(Long kakaoId, String nickname, String email, String petSize, String phoneNumber) {
        Pet pet = createNewPet("Default Pet for " + nickname, petSize);

        User newUser = User.builder()
                .userName(nickname)
                .userEmail(email)
                .userPhoneNumber(phoneNumber)
                .pet(pet)
                .build();

        usersRepository.save(newUser);
        log.info("New User created with ID: {}", newUser.getUserId());
        return newUser;
    }

    private void createNewKakaoApiUserLogin(Long kakaoId, String nickname, String accessToken, String refreshToken, User user) {
        KakaoApiUserLogin kakaoApiUserLogin = new KakaoApiUserLogin();
        kakaoApiUserLogin.setKakaoApiUserId(kakaoId);
        kakaoApiUserLogin.setKakaoApiUserName(nickname);
        kakaoApiUserLogin.setKakaoApiAccessToken(accessToken);
        kakaoApiUserLogin.setKakaoApiRefreshToken(refreshToken);
        kakaoApiUserLogin.setUser(user);

        kakaoApiUserLoginRepository.save(kakaoApiUserLogin);
        log.info("New KakaoApiUserLogin created for User ID: {}", user.getUserId());
    }

    private void updateExistingUserLogin(User user, Long kakaoId, String accessToken, String refreshToken, String nickname, String phoneNumber) {
        user.setUserName(nickname);
        user.setUserPhoneNumber(phoneNumber);
        usersRepository.save(user);

        KakaoApiUserLogin kakaoApiUserLogin = kakaoApiUserLoginRepository.findByKakaoApiUserId(kakaoId);
        if (kakaoApiUserLogin == null) {
            createNewKakaoApiUserLogin(kakaoId, nickname, accessToken, refreshToken, user);
        } else {
            kakaoApiUserLogin.setKakaoApiAccessToken(accessToken);
            kakaoApiUserLogin.setKakaoApiRefreshToken(refreshToken);
            kakaoApiUserLogin.setKakaoApiUserName(nickname);
            kakaoApiUserLoginRepository.save(kakaoApiUserLogin);
        }

        log.info("Updated existing user and KakaoApiUserLogin for User ID: {}", user.getUserId());
    }

    public void logout(String accessToken) {
        String logoutUri = "https://kapi.kakao.com/v1/user/logout";

        WebClient webClient = WebClient.builder()
                .baseUrl(logoutUri)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();

        try {
            webClient.post()
                    .retrieve()
                    .bodyToMono(Void.class)
                    .block();

            log.info("Successfully logged out from Kakao with accessToken: {}", accessToken);
        } catch (Exception e) {
            log.error("Error occurred during Kakao logout: {}", e.getMessage());
            throw new RuntimeException("Failed to logout from Kakao", e);
        }
    }
}
