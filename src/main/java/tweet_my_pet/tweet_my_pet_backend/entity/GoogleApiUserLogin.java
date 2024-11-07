package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "google_api_user_login", schema = "tweet_my_pet")
public class GoogleApiUserLogin {
    @Id
    @Column(name = "google_api_id", nullable = false)
    private Long id;

    @Column(name = "google_api_user_name", length = 45)
    private String googleApiUserName;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "google_api_access_token", nullable = false)
    private String googleApiAccessToken;

    @Column(name = "google_api_refresh_token", nullable = false)
    private String googleApiRefreshToken;

}