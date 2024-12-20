package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "company_introduce_picture")
public class StoreIntroducePicture {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "company_introduce_picture_id", nullable = false)
    private Long companyIntroducePictureId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_introduce_id", nullable = false)
    private StoreIntroduce storeIntroduce;

    @Column(name = "company_introduce_picture_content", nullable = false)
    private String companyIntroducePictureContent;

}