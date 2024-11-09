package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "no_api_user_login", schema = "tweet_my_pet")
public class NoApiUserLogin {
    @Id
    @Column(name = "no_api_login_user_id", nullable = false)
    private Long loginId;

    @Column(name = "no_api_login_user_login_id", nullable = false, length = 45)
    private String noApiLoginUserLoginId;

    @Column(name = "no_api_login_user_passwoed", nullable = false)
    private String noApiLoginUserPasswoed;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

}