package tweet_my_pet.tweet_my_pet_backend.entity.room;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;

import java.util.List;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "room")
public class Room {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "room_id", nullable = false)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_id", nullable = false)
    private Store store;

    private String roomType;        // 방 종류
    private int pricePerNight;      // 1박당 가격
    private int totalRoomCount;     // 총 방 개수

    @OneToMany(mappedBy = "room", fetch = FetchType.LAZY)
    private List<RoomAvailability> roomAvailabilities;

    @OneToMany(mappedBy = "room", fetch = FetchType.LAZY)
    private List<Reservation> reservations;
}
