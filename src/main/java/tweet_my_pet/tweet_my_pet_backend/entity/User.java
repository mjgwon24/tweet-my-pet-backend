package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Reservation;

import java.util.List;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @OneToOne(fetch = FetchType.LAZY, optional = true, cascade = CascadeType.ALL) // CascadeType.ALL 추가
    @JoinColumn(name = "pet_id", nullable = true)
    private Pet pet;

    @Column(name = "user_name", nullable = false, length = 45)
    private String userName;

    @Column(name = "user_phone_number", nullable = false, length = 45)
    private String userPhoneNumber;

    @Column(name = "user_email", nullable = false, length = 45)
    private String userEmail;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private List<Reservation> reservations;
}
