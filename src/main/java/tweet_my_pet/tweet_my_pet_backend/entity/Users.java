package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
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

    // 일반 사용자 로그인 필드
    @Column(unique = true, nullable = true)
    private String loginId; // 일반 로그인 ID (카카오 사용자는 null일 수 있음)

    private String password; // 비밀번호 (카카오 로그인 사용자에게는 필요 없음)

    private String name;

    @Column(unique = true, nullable = true)
    private String phoneNumber; // 전화번호 (옵션 필드)

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


