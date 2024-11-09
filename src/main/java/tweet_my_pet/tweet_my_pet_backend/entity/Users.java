package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter @Setter
@NoArgsConstructor
public class Users {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    // 카카오 관련 필드
    @Column(unique = true, nullable = true) // 카카오 ID는 유니크하게 설정
    private String kakaoId;

    @Column(nullable = false)
    private String nickname;

    @Column(unique = true, nullable = false)
    private String email;

    private String profileImageUrl;

    @Column(unique = true)
    private String loginId;
    private String password;
    private String name;
    private String phoneNumber;

    @Builder
    public Users(String loginId, String password, String name, String phoneNumber,
                 String kakaoId, String nickname, String email, String profileImageUrl) {
        this.loginId = loginId;
        this.password = password;
        this.name = name;
        this.phoneNumber = phoneNumber;
        this.kakaoId = kakaoId;
        this.nickname = nickname;
        this.email = email;
        this.profileImageUrl = profileImageUrl;
    }
}
