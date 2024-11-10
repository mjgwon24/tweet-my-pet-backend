package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "no_api_user_login", schema = "tweet_my_pet")
public class NoApiUserLogin {
    @Id
    @Column(name = "no_api_login_user_id", nullable = false)
    private Long noApiLoginUserLoginId;

    @Column(name = "no_api_login_user_login_id", nullable = false, length = 45)
    private String LoginId;

    @Column(name = "no_api_login_user_passwoed", nullable = false)
    private String Passwoed;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}