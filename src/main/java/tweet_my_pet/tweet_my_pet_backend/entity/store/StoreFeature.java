package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.*;
import lombok.*;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;

import java.util.List;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
@Table(name = "store_feature")
public class StoreFeature {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_feature_id", nullable = false)
    private Long id;

    @ElementCollection
    @Enumerated(EnumType.STRING)
    private List<PetSizeType> acceptPetSizes; // 수용 가능한 견종 사이즈 리스트 (대형, 중형, 소형)

    private Boolean isParking;              // 주차 가능 여부
    private Boolean isDogPark;              // 애견운동장 보유 여부
    private Boolean isDogSwimmingPool;      // 애견수영장 보유 여부
    private Boolean isInternet;             // 무선인터넷 가능 여부
    private Boolean isBarbecue;             // 바비큐 시설 보유 여부
}
