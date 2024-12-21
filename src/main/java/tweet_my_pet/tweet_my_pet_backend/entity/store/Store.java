package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.*;
import lombok.*;
import org.locationtech.jts.geom.Point;

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

    @Column(name = "store_point", nullable = false,
            columnDefinition = "geometry(Point, 4326)")
    private Point storePoint; //위도 경도 postgis 반영

    @Column(length = 45)
    private String storePresidentName;

    private String petGuide;
    private String useGuide;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "store_introduce_id")
    private StoreFeature storeFeature;
}