package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "kakao_api_user_login")
public class KakaoApiUserLogin {
    @Id
    @Column(name = "kakao_api_user_id", nullable = false)
    private Long kakaoApiUserId;

    @Column(name = "kakao_api_user_name", nullable = false, length = 45)
    private String kakaoApiUserName;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "kakao_api_access_token", nullable = false, length = 255)
    private String kakaoApiAccessToken;

    @Column(name = "kakao_api_refresh_token", nullable = false)
    private String kakaoApiRefreshToken;

}