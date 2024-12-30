package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.geo.Point;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;

import java.util.ArrayList;
import java.util.List;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
@Table(name = "store")
public class Store {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_id", nullable = false)
    private Long id;

    @Column(nullable = false, length = 45)
    private String storeName;

    @Column(nullable = false, length = 45)
    private String storeTel;

    @Column(nullable = false)
    private String storeLocation;

    @Column(nullable = false)
    private Point storePoint; // 위도, 경도

    @Column(length = 45)
    private String storePresidentName;

    @Enumerated(EnumType.STRING)
    private StoreCategory storeCategory;

    private double rating;
    private int reviewCount;
    private String petGuide;
    private String useGuide;
    private String thumbPath;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "store_feature_id")
    private StoreFeature storeFeature;

    @Builder.Default
    @OneToMany(mappedBy = "store", cascade = CascadeType.ALL)
    private List<Room> rooms = new ArrayList<>();
}