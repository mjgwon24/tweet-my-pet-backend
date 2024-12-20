package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.locationtech.jts.geom.Point;

@Getter
@Setter
@Entity
@Table(name = "store")
public class Store {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_id", nullable = false)
    private Long storeId;

    @Column(name = "store_name", nullable = false, length = 45)
    private String storeName;

    @Column(name = "store_tel", nullable = false, length = 45)
    private String storeTel;

    @Column(name = "store_location", nullable = false)
    private String storeLocation;

    @Column(name = "store_point", nullable = false, columnDefinition = "POINT")
    private Point storePoint;

    @Column(name = "store_president_name", nullable = true, length = 45)
    private String storePresidentName;
}