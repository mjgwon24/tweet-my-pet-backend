package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

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
}