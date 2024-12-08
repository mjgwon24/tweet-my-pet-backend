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
@Table(name = "no_api_user_login")
public class NoApiUserLogin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto Increment 설정 (필요 시)
    @Column(name = "no_api_login_user_id", nullable = false)
    private Long noApiLoginUserId;

    @Column(name = "no_api_login_user_login_id", nullable = false, length = 45)
    private String loginId;

    @Column(name = "no_api_login_user_password", nullable = false)
    private String password;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
