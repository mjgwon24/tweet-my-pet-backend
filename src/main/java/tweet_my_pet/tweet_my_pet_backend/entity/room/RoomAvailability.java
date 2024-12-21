package tweet_my_pet.tweet_my_pet_backend.entity.room;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "room_availability")
public class RoomAvailability {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "room_availability_id", nullable = false)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "room_id", nullable = false)
    private Room room;

    private LocalDate date;         // 조회 날짜
    private int availableRoomCount; // 예약가능 방 개수
}
