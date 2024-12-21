package tweet_my_pet.tweet_my_pet_backend.entity.room;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

import java.time.LocalDateTime;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "reservation")
public class Reservation {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "reservation_id", nullable = false)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "room_id", nullable = false)
    private Room room;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private LocalDateTime checkInDateTime;  // 체크인 시간
    private LocalDateTime checkOutDateTime; // 체크아웃 시간
    private int totalPrice;                 // 총 가격
    private boolean isCanceled;             // 취소 여부
}
