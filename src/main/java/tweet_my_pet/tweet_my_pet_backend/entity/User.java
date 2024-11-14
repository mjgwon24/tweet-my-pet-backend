package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.util.Date;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users", schema = "tweet_my_pet")
public class User {
    @Id
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "pet_id", nullable = false)
    private Pet pet;

    @Column(name = "user_name", nullable = false, length = 45)
    private String userName;

    @Column(name = "user_phone_number", nullable = false, length = 45)
    private String userPhoneNumber;

    @Column(name = "user_email", nullable = false, length = 45)
    private String userEmail;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_gender", nullable = false)
    private Gender gender;

    public enum Gender {
        남, 여
    }

    @Column(name = "user_birth", nullable = false)
    private Date birth;
}