package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "naver_api_user_login")
public class NaverApiUserLogin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "naver_api_user_id", nullable = true)
    private Long naverApiUserId;

    @Column(name = "naver_api_user_name", nullable = false, length = 45)
    private String naverApiUserName;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "naver_api_access_token", nullable = false, length = 255)
    private String naverApiAccessToken;

    @Column(name = "naver_api_refresh_token", nullable = false, length = 255)
    private String naverApiRefreshToken;

}