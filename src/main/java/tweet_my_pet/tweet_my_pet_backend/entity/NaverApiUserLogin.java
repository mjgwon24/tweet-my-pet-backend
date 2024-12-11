package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "naver_api_user_login")
public class NaverApiUserLogin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "naver_api_user_id", nullable = false)
    private Long naverApiUserId;

    @Column(name = "naver_api_user_name", nullable = false, length = 45)
    private String naverApiUserName;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "naver_api_access_token", nullable = false)
    private String naverApiAccessToken;

    @Column(name = "naver_api_refresh_token", nullable = false, length = 45)
    private String naverApiRefreshToken;

}